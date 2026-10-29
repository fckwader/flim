import crypto from "crypto";
import { WebSocket } from "ws";
import { addWsEgress } from "./egress";
import { LOCK_TTL_MS, NotesMode, Op, PeerInfo, Role, ServerMsg, UnitKey, UserInfo } from "./protocol";

export interface Client {
  ws: WebSocket;
  user: UserInfo;
  role: Role;
  alive: boolean; // for ping/pong liveness
  ip: string;
}

interface Lock {
  owner: string; // user id
  at: number;
}

export function send(ws: WebSocket, msg: ServerMsg): void {
  if (ws.readyState !== WebSocket.OPEN) return;
  const data = JSON.stringify(msg);
  addWsEgress(ws, Buffer.byteLength(data));
  ws.send(data);
}

const sha = (v: string) => crypto.createHash("sha256").update(v, "utf8").digest();

// One session = one slot. Everything a session holds (clients, locks, snapshot, ops, sample
// files via blobKey) stays inside it: no message from one session ever reaches another.
export class Session {
  readonly code: string;
  readonly blobKey = crypto.randomBytes(32).toString("hex"); // sample store access (blobs.ts)
  leaderId: string;
  lastActive = Date.now(); // any message from any member; idle sessions are closed
  readonly endsAt: number | null; // time limit (null = none)
  readonly notesMode: NotesMode;   // the host's choice, fixed for the session
  private pwHash: Buffer;
  private ended = false;
  private clients = new Set<Client>();
  private locks = new Map<UnitKey, Lock>();
  private seq = 0;
  private flp: string | null = null;
  private epoch = 0;
  private onEmpty: () => void;

  constructor(code: string, password: string, leader: Client, endsAt: number | null, onEmpty: () => void,
              notesMode: NotesMode = "lock") {
    this.code = code;
    this.endsAt = endsAt;
    this.notesMode = notesMode;
    this.pwHash = sha(password);
    this.leaderId = leader.user.id;
    this.onEmpty = onEmpty;
    this.add(leader);
  }

  passwordOk(given: unknown): boolean {
    return crypto.timingSafeEqual(sha(typeof given === "string" ? given : ""), this.pwHash);
  }

  hasUser(id: string): boolean {
    for (const c of this.clients) if (c.user.id === id) return true;
    return false;
  }

  touch(): void {
    this.lastActive = Date.now();
  }

  ips(): string[] {
    return [...new Set([...this.clients].map((c) => c.ip))];
  }

  // Close the session for everyone (idle / time limit): the slot is free again.
  end(code: string, msg: string, cooldown?: number): void {
    for (const c of this.clients) {
      send(c.ws, { t: "error", code, msg, ...(cooldown ? { cooldown } : {}) });
      c.ws.close(4002, code);
    }
    this.clients.clear();
    this.locks.clear();
    this.flp = null;
    this.finish();
  }

  private finish(): void {
    if (this.ended) return;
    this.ended = true;
    this.onEmpty();
  }

  get size(): number {
    return this.clients.size;
  }

  private peers(): PeerInfo[] {
    return [...this.clients].map((c) => ({ id: c.user.id, name: c.user.name, role: c.role }));
  }

  private broadcast(msg: ServerMsg, except?: Client): void {
    for (const c of this.clients) if (c !== except) send(c.ws, msg);
  }

  private clientOf(ws: WebSocket): Client | undefined {
    for (const c of this.clients) if (c.ws === ws) return c;
    return undefined;
  }

  add(client: Client): void {
    this.clients.add(client);
    send(client.ws, {
      t: "welcome", session: this.code, role: client.role, you: client.user, peers: this.peers(), blob: this.blobKey,
      ends_in: this.endsAt === null ? 0 : Math.max(1, this.endsAt - Date.now()), notes: this.notesMode,
    });
    send(client.ws, { t: "snapshot", flp: this.flp, epoch: this.epoch });
    send(client.ws, { t: "lock_state", locks: [...this.locks].map(([key, l]) => ({ key, owner: l.owner })) });
    this.broadcast({ t: "presence", peers: this.peers() }, client);
  }

  // Leader seeds the initial project blob (host upload).
  setSnapshot(from: Client, flp: string): void {
    if (from.user.id !== this.leaderId) {
      send(from.ws, { t: "error", code: "not_leader", msg: "Only the party leader can set the project." });
      return;
    }
    this.flp = flp;
    // epoch unchanged for the initial seed; members already got it via welcome/snapshot
    this.broadcast({ t: "snapshot", flp: this.flp, epoch: this.epoch }, from);
  }

  // Leader swaps the whole project; members must resync. Clears all locks.
  projectSwap(from: Client, flp: string): void {
    if (from.user.id !== this.leaderId) {
      send(from.ws, { t: "error", code: "not_leader", msg: "Can't change FLP as non party leader" });
      return;
    }
    this.flp = flp;
    this.epoch += 1;
    this.locks.clear();
    this.broadcast({ t: "project_swap", flp, epoch: this.epoch }, from);
  }

  relayOp(from: Client, op: Op): void {
    // Backstop: if the op targets a unit locked by someone else, reject it.
    if (op.key) {
      const l = this.locks.get(op.key);
      if (l && l.owner !== from.user.id) {
        send(from.ws, { t: "error", code: "locked", msg: `Unit ${op.key} is locked by ${l.owner}` });
        return;
      }
    }
    this.seq += 1;
    this.broadcast({ t: "op", seq: this.seq, from: from.user.id, op }, from);
  }

  acquire(from: Client, key: UnitKey): void {
    const now = Date.now();
    const existing = this.locks.get(key);
    if (existing && existing.owner !== from.user.id && now - existing.at < LOCK_TTL_MS) {
      send(from.ws, { t: "lock", key, granted: false, owner: existing.owner });
      return;
    }
    this.locks.set(key, { owner: from.user.id, at: now });
    send(from.ws, { t: "lock", key, granted: true, owner: from.user.id });
    this.broadcast({ t: "lock", key, granted: true, owner: from.user.id }, from);
  }

  release(from: Client, key: UnitKey): void {
    const l = this.locks.get(key);
    if (l && l.owner === from.user.id) {
      this.locks.delete(key);
      this.broadcast({ t: "lock_released", key });
    }
  }

  // Safety sweep: drop locks whose owner went silent past the TTL.
  sweepLocks(): void {
    const now = Date.now();
    for (const [key, l] of this.locks) {
      if (now - l.at >= LOCK_TTL_MS) {
        this.locks.delete(key);
        this.broadcast({ t: "lock_released", key });
      }
    }
  }

  // Refresh a lock's timestamp while its owner keeps editing (op heartbeat).
  touchLocksOf(userId: string): void {
    const now = Date.now();
    for (const l of this.locks.values()) if (l.owner === userId) l.at = now;
  }

  remove(ws: WebSocket): void {
    const client = this.clientOf(ws);
    if (!client) return;
    this.clients.delete(client);

    // release this user's locks
    for (const [key, l] of this.locks) {
      if (l.owner === client.user.id) {
        this.locks.delete(key);
        this.broadcast({ t: "lock_released", key });
      }
    }

    // leader leaving ends the session (handoff is a later feature)
    if (client.user.id === this.leaderId) {
      for (const c of this.clients) {
        send(c.ws, { t: "leader_left" });
        c.ws.close(4000, "leader_left");
      }
      this.clients.clear();
    } else {
      this.broadcast({ t: "presence", peers: this.peers() });
    }

    if (this.clients.size === 0) {
      this.locks.clear();
      this.flp = null;
      this.finish();
    }
  }

  allClients(): Client[] {
    return [...this.clients];
  }
}
