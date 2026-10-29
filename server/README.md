# flim-server

WebSocket relay for [flim](../README.md). It doesn't understand FL Studio. It:
- puts every edit (`op`) in one order and relays it to the other people in the session,
- gives out per-unit **locks** (a knob, a pattern, the playlist) so two people can't edit the
  same thing at once; locks expire after 30 s if a client stops releasing them,
- runs **one session** (`01`), with a password set by its host. With `FLIM_PASSWORD` set, only a host
  that sends it (as `owner`; Ctrl+click Host in flim) may open the session,
- tracks who's in the session (the host is the leader; if the leader leaves, the session ends),
- stores **sample files** per session so each one is uploaded once and the others fetch only what
  they're missing (`src/blobs.ts`, plain HTTP on the same port).

**Public mode** (`FLIM_PUBLIC=1`, the public test server flim.fly.dev): up to 8 sessions (`01`-`08`,
first free one for each new host) plus the owner's `00` (only for a host that sends `FLIM_OWNER_KEY`,
or `FLIM_PASSWORD`). Sessions are fully separate: ops, locks, projects and sample files never cross.
Sessions `01`-`08` end after 15 minutes (`FLIM_SESSION_MS`; `welcome` carries `ends_in` ms, the kick is
`time_up` with `cooldown` ms); every IP that was in one then can't host or join another one for 5
minutes (`FLIM_COOLDOWN_MS`; refused with `cooldown` + `retry_in`); sessions without any message for
5 minutes are closed (`FLIM_IDLE_MS`). Slot `00` has no time limit and no cooldown.

Data budget (optional, `src/egress.ts`): `FLIM_EGRESS_DAY_GB` caps what the server sends per UTC day
(WebSocket messages + sample downloads) for everyone together, `FLIM_EGRESS_IP_DAY_GB` per client IP.
Over it, new sessions / joins are refused (`data_limit`) and sample downloads get 429; running sessions
keep going. Unset = no limit. Useful on a public server: outbound data is what a host bills for.

Limits: 8 people per session, 12 WebSockets per IP (`FLIM_MAX_CONNS_PER_IP`), 8 wrong passwords /
owner keys per IP per 10 minutes, 400 messages/s per connection (bursts up to 4000).

Sessions are kept in memory only. When the machine stops, they are gone; the next host starts a new
one from their project.

## Sample store
Content-addressed by SHA-256, one folder per session (deleted when the session ends). Auth: header
`x-flim-key` = the session's blob key from `welcome`; it only reaches that session's files.
| Request | Does |
|---|---|
| `POST /blobs/missing` | body: one hash per line → the ones not stored, one per line |
| `HEAD /blob/<sha256>` | 200 + `content-length`, or 404 |
| `GET /blob/<sha256>` | the file |
| `PUT /blob/<sha256>` | store it (streamed to disk; rejected unless the content hashes to `<sha256>`) |

| Variable | Default |
|---|---|
| `FLIM_BLOB_DIR` | `<system temp>/flim-blobs` |
| `FLIM_BLOB_SESSION_MAX` | 2500 MB per session; its least recently used files are deleted above it |
| `FLIM_BLOB_STORE_MAX` | 5 GB for all sessions together; uploads are refused (507) above it |
| `FLIM_BLOB_FILE_MAX` | 2000 MB per file |

On fly.io the disk is reset when the machine stops, which is fine for a cache. Sample downloads
count towards fly.io's outbound data transfer.

## Run locally
Requires Node.js 20+.
```bash
npm install
npm run build
npm start                 # :8080, or set PORT
npm run dev               # auto-restarting dev mode (tsx watch)
curl http://localhost:8080/health    # -> flim-server ok
```
Set `FLIM_PASSWORD` so only you (or whoever you tell) can host. `npm test` runs the session tests.

## Deploy to fly.io
```bash
fly auth login
fly launch --no-deploy --copy-config --name <your-unique-app-name>
fly secrets set FLIM_PASSWORD=<something-long>     # optional: only who knows it can host
fly deploy
fly scale count 1                                    # sessions live in one process: keep one machine
```
Hosts enter `<your-unique-app-name>.fly.dev`; the session link is
`https://<your-unique-app-name>.fly.dev/01` (opened in a browser, they show a short how-to page).

- `fly.toml` scales to zero (`auto_stop_machines = "stop"`, `min_machines_running = 0`): no cost
  while idle, and it wakes in a second or two when someone connects. Set `min_machines_running = 1`
  for an always-warm instance.
- Change `primary_region` to the region closest to you and your friends (`fly platform regions`).
- `MAX_PAYLOAD` in `src/server.ts` (64 MB) limits the size of a project sent as one message.

## Protocol
JSON over WebSocket; see `src/protocol.ts`. A host sends
`{"t":"host","password":"…","user":{"id":"…","name":"…"}}` (plus `"owner":"…"`: the server password, or
slot `00` in public mode), a member
`{"t":"join","session":"03","password":"…","user":{…}}`. Both get `welcome` (session, role, peer list,
blob key), then exchange `op`, `lock_acquire` / `lock_release` (→ `lock`, `lock_released`), and receive
`presence` updates. Ops that carry a project or a plugin state may list the samples it uses
(`"samples":[{"p":…,"h":<sha256>,"s":<bytes>}]`), fetched from `/blob/<h>`. Refusals are
`{"t":"error","code":…}` (`full`, `no_session`, `bad_password`, `bad_owner`, `owner_required`, `in_use`, `session_full`,
`too_many_attempts`, …) followed by close code 4001; an idle session ends with `idle` and code 4002.
