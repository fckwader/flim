// Outbound data budget (public test server: keeps the hosting bill bounded). Counts what the
// server sends - WebSocket messages and sample downloads - per UTC day, in total and per client
// IP (Fly's proxy passes the IP per request, so this is counted here, not per socket). Over the
// budget, new sessions and sample downloads are refused; running sessions keep going.
//   FLIM_EGRESS_DAY_GB     all clients together per UTC day (unset / 0 = no limit)
//   FLIM_EGRESS_IP_DAY_GB  one IP per UTC day (unset / 0 = no limit)
// In memory: a restart starts the count over (a busy server doesn't stop, an idle one doesn't spend).
import { WebSocket } from "ws";

const GB = 1024 * 1024 * 1024;
const DAY_MAX = Number(process.env.FLIM_EGRESS_DAY_GB ?? 0) * GB;
const IP_MAX = Number(process.env.FLIM_EGRESS_IP_DAY_GB ?? 0) * GB;

let day = "";
let total = 0;
const perIp = new Map<string, number>();
const wsIp = new WeakMap<WebSocket, string>();

function today(): void {
  const d = new Date().toISOString().slice(0, 10);
  if (d !== day) {
    if (day) console.log(`[egress] ${day}: ${(total / GB).toFixed(2)} GB sent`);
    day = d;
    total = 0;
    perIp.clear();
  }
}

export function setWsIp(ws: WebSocket, ip: string): void {
  wsIp.set(ws, ip);
}

export function addEgress(ip: string | undefined, bytes: number): void {
  today();
  total += bytes;
  if (ip) perIp.set(ip, (perIp.get(ip) ?? 0) + bytes);
}

export function addWsEgress(ws: WebSocket, bytes: number): void {
  addEgress(wsIp.get(ws), bytes);
}

// null = fine; otherwise why not (shown to the user)
export function egressRefusal(ip: string): string | null {
  today();
  if (DAY_MAX && total >= DAY_MAX) return "The server reached its data limit for today (UTC). Try again tomorrow.";
  if (IP_MAX && (perIp.get(ip) ?? 0) >= IP_MAX) return "Your connection reached its data limit for today (UTC). Try again tomorrow.";
  return null;
}

export function egressLimits(): string {
  const f = (v: number) => (v ? `${v / GB} GB` : "none");
  return `data per day: ${f(DAY_MAX)} total, ${f(IP_MAX)} per IP`;
}
