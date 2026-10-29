// flim wire protocol. JSON messages over WebSocket; the `.flp` snapshot is
// carried as base64 in `flp`. Keep this file in sync with the FL client.

export type Role = "leader" | "member";
// How simultaneous piano-roll edits combine (the host picks): "lock" = one person per pattern + channel
// at a time, "merge" = both kept (note identities, engine's notes.merge ops). Clients that can merge
// say so in join.caps; a merge session refuses members that can't.
export type NotesMode = "lock" | "merge";
export const CAP_NOTES_MERGE = "notes.merge";

export interface UserInfo {
  id: string;
  name: string;
}

export interface PeerInfo {
  id: string;
  name: string;
  role: Role;
}

// A unit key identifies the lockable edit atom (see docs/NETWORKING.md).
//  - parameter:   `param:<recEventId>`
//  - mixer track: `mixtrack:<index>`
//  - channel:     `chan:<flimUid>`
//  - note:        `note:<patternUid>:<noteUid>`   (or `group:<patternUid>:<groupId>`)
//  - clip:        `clip:<flimUid>`
//  - pattern:     `pat:<flimUid>`
export type UnitKey = string;

// An op is opaque to the server: it only orders and relays it. The FL client
// defines/interprets the payload. `key` (optional) ties the op to a lock unit.
// `samples` (optional, project.load / plug.state / chan.add) lists the sample files the op's
// data uses: [{p: base64 UTF-16 path, h: sha256 hex, s: bytes}], fetched from /blob/<h> (blobs.ts).
export interface Op {
  kind: string;
  key?: UnitKey;
  [k: string]: unknown;
}

// ---- client -> server ----
export type ClientMsg =
  // host: take the first free public slot (01..08) with a new session password. `owner` = the
  // server's owner key (FLIM_OWNER_KEY) asks for the reserved slot 00 instead.
  | { t: "host"; user: UserInfo; password: string; owner?: string; notes?: NotesMode }
  | { t: "join"; user: UserInfo; session: string; password: string; caps?: string[] } // session = slot id ("03")
  | { t: "snapshot"; flp: string } // leader seeds/updates the project blob
  | { t: "project_swap"; flp: string } // leader only; replaces the project
  | { t: "op"; op: Op }
  | { t: "lock_acquire"; key: UnitKey }
  | { t: "lock_release"; key: UnitKey }
  | { t: "bye" };

// ---- server -> client ----
export type ServerMsg =
  // blob: this session's key for the sample store (header x-flim-key, see blobs.ts)
  // ends_in: ms until the session's time limit ends it (0 = no limit, slot 00)
  | { t: "welcome"; session: string; role: Role; you: UserInfo; peers: PeerInfo[]; blob: string; ends_in: number; notes: NotesMode }
  | { t: "snapshot"; flp: string | null; epoch: number }
  | { t: "op"; seq: number; from: string; op: Op }
  | { t: "lock"; key: UnitKey; granted: boolean; owner: string | null }
  | { t: "lock_state"; locks: Array<{ key: UnitKey; owner: string }> }
  | { t: "lock_released"; key: UnitKey }
  | { t: "project_swap"; flp: string; epoch: number } // members: show resync notice, reload
  | { t: "presence"; peers: PeerInfo[] }
  | { t: "leader_left" } // session is ending
  // codes: bad_json, bad_password, bad_owner, owner_required, no_session, full, in_use, id_in_use, session_full,
  // bad_request, too_many_attempts, too_many_connections, data_limit, cooldown (+retry_in ms), idle / time_up
  // (session closed; time_up + cooldown ms), not_joined, not_leader, locked, unknown
  | { t: "error"; code: string; msg: string; retry_in?: number; cooldown?: number };

export const LOCK_TTL_MS = 30_000; // safety auto-release if a client never releases
export const PING_INTERVAL_MS = 15_000;
