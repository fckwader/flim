# flim

**Real-time multiplayer for FL Studio 2025.** Two or more people each run their own FL Studio, with their
own windows, zoom and selection, while the song itself (knobs, plugins, channels, notes, playlist, mixer,
samples) is kept in sync over the internet. It works a bit like [Drawpile](https://drawpile.net/), but for FL.

> 🚧 **Still missing features.** A few things don't sync yet, such as samples inside Kontakt and
> other people's selection. See [What's synced](#whats-synced) for the full list.

> ⚠️ **Unofficial and experimental.** flim is not made by, affiliated with or endorsed by Image-Line.
> It works by running extra code inside FL Studio's process, and it only supports **specific FL builds**
> (see [Requirements](#requirements)). It can crash FL, so save often. flim never overwrites your
> original `.flp` files (see [Sessions](#sessions)).

---

## ! PUBLIC TEST !

**Try flim with a friend right now, no server needed.** There is a public test server at
**`flim.fly.dev`** with 8 session slots.

1. You both need **FL Studio 2025, build 25.2.3.5171** (Help > About) on Windows 10/11. Different
   build? See [Other FL Studio builds](#other-fl-studio-builds).
2. Download `flim-client-win64.zip` from the [latest release](../../releases/latest), unzip it, and run
   **`flim.exe`**. The first time, it asks for your FL Studio folder and a name.
3. **One of you hosts:** in FL's top toolbar (next to the CPU / memory meters) click **Host**. The
   server is already filled in (`flim.fly.dev`) and so is a random session password (change it if you
   like). Click **Host**. flim shows your **session link** (e.g. `https://flim.fly.dev/03`) and the
   **password**, with a **Copy** button. Send both to your friend.
4. **The other joins:** click **Connect**, paste the link, enter the password, click **Connect**. Your
   friend's FL now loads the host's project, and from then on you're making the same song.

Rules of the public test:
- **Sessions last 15 minutes**, so nobody hogs a slot. The time left is shown at the right end of
  flim's toolbar. When it runs out, everyone is disconnected, and **you keep all progress in your
  FL**: save it as usual.
- After a session's time runs out, everyone who was in it waits a **5-minute cooldown** (shown as
  `COOLDOWN: mm:ss`) before hosting or joining again.
- A session where nobody does anything for 5 minutes is closed.
- If all 8 slots are taken, Host tells you so. Try again a bit later.
- Up to 8 people per session. If the host leaves, the session ends.

Want no time limit? [Run your own server](#server): it's one `npm start`, and it has no limits.

---

## How it works

```
 you                                  server                         friend
┌────────────────────────┐        ┌──────────────┐        ┌────────────────────────┐
│ flim.exe starts FL and │   ws   │ flim-server  │   ws   │ flim.exe starts FL and │
│ loads flim_engine.dll  │◄──────►│ orders edits │◄──────►│ loads flim_engine.dll  │
│ into it                │        │ hands out    │        │ into it                │
│  - notices your edits  │        │ edit locks   │        │  - applies your edits  │
│  - applies theirs      │        │ (Node.js)    │        │  - sends theirs        │
└────────────────────────┘        └──────────────┘        └────────────────────────┘
```

- **`flim.exe`** (the launcher) starts your normal FL Studio and loads the flim engine into it. Nothing in
  your FL Studio installation is modified on disk.
- **`flim_engine.dll`** (the engine) runs inside FL. It watches for local edits, sends them to the server,
  and applies everyone else's edits through FL's own internal functions, so FL's UI stays consistent.
  It adds **Connect** and **Host** buttons to FL's top toolbar.
- **`flim-server`** is a small WebSocket relay. It puts edits in one order for everyone and gives out locks,
  so two people can't edit the same pattern or knob at the same moment. One person (or a server
  somewhere) runs it, and everyone connects to it.

### What's synced
| Synced | Not yet |
|---|---|
| Tempo, main volume, main pitch, shuffle | Samples inside plugins that store them compressed or encrypted (Kontakt, ...) |
| Channel volume / pan / on-off / mixer routing | Showing other people's selection inside an editor |
| Every plugin parameter (generators and effects) | |
| Full plugin state (presets, wavetables, ...) | |
| Mixer volume / pan / stereo separation / mute | |
| Mixer track names, colors and routing (sends on/off and send levels) | |
| Adding, deleting and reordering channels; channel names and colors | |
| Adding, replacing and removing mixer effects | |
| Notes in every pattern; pattern names, colors and length (so new patterns too) | |
| Inserting, cloning, deleting and splitting patterns (later patterns move along) | |
| Playlist clips; playlist track names and colors | |
| Playlist markers (including time signature markers); the project's time signature | |
| Time signatures of single patterns (pattern menu) and piano roll markers | |
| Automation clips | |
| Sample files used by channels, audio clips and plugins like FPC (see [Samples](#samples)) | |
| Opening or loading a project (the leader's project is sent to everyone) | |
| Which window everyone is working in, and where their mouse is in the piano roll and playlist (see [Who's where](#whos-where)) | |

**Locks:** while you turn a knob, edit one instrument's notes in a pattern or edit a playlist track,
that part is yours. Locks are small, so two people rarely collide: every knob (including every plugin
parameter) is locked on its own, a pattern's notes per channel (you on the kick, your friend on the hats
of the same pattern is fine), and the playlist per track. A whole plugin is only locked while its preset
or state changes. If someone else touches your part at the same time, their change is undone and FL's
hint bar shows *"Channel 2 in pattern 3 is being edited by Alex"*. Locks are released shortly after you
stop (about 0.6 s for a knob, 1 s for notes and playlist tracks).
Names, colors, routing, markers and the time signature have no locks; if two people change the same
one at the same moment, the leader's change wins.

**Lock or Merge for notes:** whoever hosts picks how notes behave when two people edit the *same*
instrument in the same pattern at once (the **(i)** next to the choice in the Host dialog explains it):
- **Lock** (default): one person at a time, as above.
- **Merge**: both people's notes are kept and combined, nothing is undone. Merge is
  [cashflowbeatz](https://github.com/cashflowbeatz)'s note merging (a CRDT, `client/common/flim_notes_crdt.h`).

**Fast changes:** when you scroll a knob or the tempo quickly (130 → 131 → … → 140), flim sends the
latest value instead of every step, and the receiving side skips steps that are already outdated.

### Who's where
The status next to the Connect button shows the window each other person last clicked or typed in,
e.g. `Connected to flim.example.com · leader · 2 people · Alex: Piano roll - Kick · Pattern 3`.
Hover over it to see everyone in FL's hint bar.

When someone's mouse is over the piano roll or the playlist, you see a small arrow with their name at
the same spot in yours (the same note and bar, whatever your zoom or scroll), as long as you are looking
at the same pattern or arrangement. The arrows can't be clicked and never get in your way.

**What others just changed glows in their color** and fades out over 1.5 seconds: notes they added or
changed in the piano roll, clips in the playlist, and for knobs the window the knob is in (the plugin or
effect window if it's open, otherwise the channel rack or the mixer). Exact knobs can't be outlined:
FL draws its mixer and channel rack as one picture, and plugin windows are a closed box to FL.

---

## Requirements

- **Client:** Windows 10 or 11 (64-bit) and **FL Studio 2025, build 25.2.3.5171** (Help → About).
  Have a different build? See [Other FL Studio builds](#other-fl-studio-builds).
- **Server:** any machine with Node.js 20 or newer (Windows, Linux or macOS) that everyone can reach.

---

## Quick start

### Client
1. Download `flim-client-win64.zip` from [Releases](../../releases) and unzip it anywhere.
   Keep `flim.exe` and `flim_engine.dll` in the same folder.
2. Double-click **`flim.exe`**. The first time, it asks for:
   - your **FL Studio 2025 folder** (the one that contains `FL64.exe`, usually
     `C:\Program Files (x86)\Image-Line\FL Studio 2025`). It is checked right away.
   - a **name** that the others will see (letters, digits, spaces, `- _ .`, up to 24 characters).
3. FL Studio opens. In the top toolbar, to the right of the meters:

   `[ Connect ] [ Host ] [ Rooms ]  ● Not connected`

   (**Rooms** opens cashflowbeatz's separate flimrooms app, see [Rooms](#rooms-by-cashflowbeatz).)

4. **To start a session**, click **Host**. Enter the server (e.g. `flim.fly.dev`) and a session
   password (a random one is filled in; change it if you like), pick **Lock** or **Merge** for notes
   (see [Lock or Merge](#whats-synced)), click **Host**. flim shows your
   **session link** (e.g. `https://flim.fly.dev/03`) and the password, with a **Copy** button: send
   both to the people you want to play with. Click the status text later to see them again.
   If every session on the server is taken, you're told so; try again later.
5. **To join**, click **Connect**, paste the session link and enter the password.
   The status turns green: `Connected to flim.fly.dev/03 · member · 2 people`.
6. Make music together. Click **Disconnect** to leave.

### Server
Only one person needs to run this.
```bash
git clone https://github.com/fckwader/flim.git
cd flim/server
npm install
npm run build
npm start
```
The server listens on port **8080**. Whoever hosts enters its address in the Host dialog:
- **Same network:** `ws://<your-LAN-IP>:8080`, e.g. `ws://192.168.1.20:8080`.
- **Over the internet:** forward TCP port 8080 on your router to this PC and use
  `ws://<your-public-IP>:8080`. Or put the server behind a reverse proxy with HTTPS and use `wss://`
  (see [Server details](#server-details)).
- **Just testing on one PC:** `localhost:8080`.

---

## Using flim

### Sessions
- A server you run yourself holds **one session** (`01`). The public test server `flim.fly.dev`
  runs up to **8** at once (`01` to `08`). Every session has its own password, and sessions are fully
  separate: nothing (edits, locks, projects, sample files) crosses from one to another.
- Whoever **hosts** a session is its **leader**.
- Anyone who joins later is a **member** and gets the leader's current project. It is saved as a copy, e.g.
  `Documents\flim\MySong_flim_1012_2130.flp`, and opened automatically.
- When the leader opens another project, it is sent to everyone. Your original `.flp` files are never
  saved over: flim always works on `*_flim_MMDD_hhmm.flp` copies.
- If the leader leaves, the session ends. The members keep their copy of the project.
- **On `flim.fly.dev` only** (testing, so nobody hogs a slot): sessions last at most **15 minutes**;
  the time left is shown at the right end of flim's toolbar. When it runs out, everyone is
  disconnected and keeps their FL project exactly as it is. Everyone who was in it then has a
  **5-minute cooldown** (shown as `COOLDOWN: mm:ss`) before hosting or joining another session. A
  session where nobody does anything for **5 minutes** is closed, so its slot is free again.

### Samples
The samples your channels, audio clips and sample-based plugins use are sent along automatically,
both when the leader's project is sent and when someone loads a new sample during the session.
- Each file is uploaded to the server **once per session**; the others download only the files they don't already
  have, into `Documents\flim\samples\`, and their copy of the project points at those files.
- While that happens, the toolbar status shows *"Uploading samples: 12.3 / 40.0 MB"* (or *Downloading*).
  Your other edits wait until the upload is done, so they arrive in the right order.
- **If more than 50 MB would have to be uploaded at once, flim asks first** and shows the exact amount,
  e.g. *"Sending them uploads 60.6 MB (63,504,132 bytes). Send them now?"*. **No** leaves those samples
  out (they will be missing for the others) and flim won't ask about them again until FL restarts.
- Samples in FL's factory content are never sent: every FL installation has them.
- Samples inside plugin states are found too: in FPC (and other newer Image-Line plugins that store
  them the same way), and as plain file paths in any other plugin's state. For the latter, the
  receiving copy points at a link to the downloaded file under `Documents\flim\samples\`, named to
  keep the plugin's data valid. Plugins that compress or encrypt their state (Kontakt, ...) aren't covered.

### Server addresses
| You type | Means |
|---|---|
| `localhost:8080` | a server on your own PC (plain `ws://`) |
| `ws://192.168.1.20:8080` | a server elsewhere on your LAN |
| `ws://203.0.113.7:8080` | a server over the internet, unencrypted |
| `wss://flim.example.com` | a server behind HTTPS (encrypted, port 443) |
| `flim.example.com` | same thing: a bare host name means `wss://`, port 443 |

### Rooms (by cashflowbeatz)
**Rooms is entirely [cashflowbeatz](https://github.com/cashflowbeatz)'s work**: the flimrooms app, its
design, its relay and the flim engine it runs are all his. flim only adds the **Rooms** button that opens it.

flimrooms is a separate Windows app: create or join a room with your name and an 8-digit code. It
starts its own FL Studio with its own flim and connects through cashflowbeatz's relay (on Cloudflare),
so the projects and samples of Rooms sessions go through his server, not `flim.fly.dev` or yours.
Rooms sessions and Host / Connect sessions don't mix.

- Download `flim-rooms-<version>-win64.exe` from the [latest release](../../releases/latest) (a
  separate download from `flim-client-win64.zip`). It's a portable app: no installer.
- Put it in a `rooms` folder next to `flim.exe`, next to `flim.exe` itself, or leave it in your
  Downloads folder, and the **Rooms** button finds it. Otherwise the button asks where it is (once) or
  takes you to the download.
- Rooms is experimental. Questions and bugs about it go to cashflowbeatz.

### Changing your settings
Run `flim.exe --setup` to change your FL folder or name. You can also change your name in the
Connect and Host dialogs.

### Where flim keeps things
| What | Where |
|---|---|
| Settings (FL folder, name, last session link and host server, password if "Remember" is ticked) | `%APPDATA%\flim\flim.ini`. Passwords are encrypted for your Windows user (DPAPI). |
| Log (attach it to bug reports) | `%TEMP%\flim_engine.log` |
| Project copies received from the leader | `Documents\flim\` |
| Samples received from others (safe to delete when no session is running) | `Documents\flim\samples\` |

---

## Server details

See [`server/README.md`](server/README.md) for the protocol and options.

- **Session:** your server holds one session (`01`), with no time limit. Whoever hosts picks its
  password; joining needs the session link and that password.
- **Server password:** set `FLIM_PASSWORD` and only someone who knows it can host (Ctrl+click
  **Host** to enter it). Without it, anyone who knows the address can host. Wrong passwords are
  rejected after a second; 8 wrong ones from one IP in 10 minutes block that IP for the rest of the
  10 minutes.
- **Limits:** 8 people per session, 12 connections per IP, and a cap on messages per second per
  connection.
- **Public mode** (`FLIM_PUBLIC=1`, what `flim.fly.dev` runs): 8 sessions plus the owner's `00`
  (`FLIM_OWNER_KEY`), 15-minute sessions with a 5-minute cooldown and an idle timeout. See
  [`server/README.md`](server/README.md).
- **Port:** 8080 by default; set `PORT` to change it.
- **Encryption:** the server speaks plain `ws://`. For `wss://`, put it behind any reverse proxy that
  handles HTTPS and WebSockets (Caddy, nginx, a cloud load balancer, ...) and forward to port 8080.
  The proxy must pass plain HTTP requests too (sample files use `/blob/...` on the same port) and allow
  large request bodies.
- **Sample store:** sample files are kept on the server's disk under their SHA-256, in a folder per
  session under `FLIM_BLOB_DIR` (default: the system temp folder), deleted when the session ends.
  `FLIM_BLOB_SESSION_MAX` caps one session (default 2500 MB; its least recently used files go first),
  `FLIM_BLOB_STORE_MAX` all of them together (default 5 GB; uploads are refused above it) and
  `FLIM_BLOB_FILE_MAX` a single file (default 2000 MB).
- **Docker:** a `Dockerfile` is included:
  ```bash
  docker build -t flim-server server
  docker run -p 8080:8080 -e FLIM_PASSWORD=pick-a-password flim-server
  ```
- **Health check:** `GET /health` answers `flim-server ok`.
- Sessions live in memory only. Restarting the server ends all sessions; run a single instance.

---

## Building the client from source

Requires **Visual Studio 2022 Build Tools** (the "Desktop development with C++" workload).
```bat
cd client
build.bat
```
`build.bat` writes `flim.exe` and `flim_engine.dll` to `client\out\`. If your Build Tools are not in the
default location, change `VCVARS` at the top of `build.bat`. Both files are plain C, linked statically,
and use only DLLs that ship with Windows.

### Developer shortcuts
These environment variables are read by the engine and skip the Connect / Host dialogs:

| Variable | Effect |
|---|---|
| `FLIM_AUTOCONNECT=<session link>` | join at startup (with `FLIM_PASSWORD=<session password>`) |
| `FLIM_HOST=1` | `FLIM_AUTOCONNECT` is a server address to host on instead (`FLIM_OWNER_KEY=<key>`: the server's password, or the owner key = slot `00` on a public server) |
| `FLIM_NAME=<name>` | override the name from `flim.ini` (e.g. to run two FLs on one PC) |
| `FLIM_SAMPLE_NOLOCAL=1` | never use a local copy of a received sample, always download it (to test sample transfer on one PC) |

`client\restart_test.ps1 [-Url localhost:8080] [-OwnerKey <server password>] [-Slot 01] [-Password test]`
closes all FL instances, rebuilds, and starts two of them: "A" hosts, "B" joins session `-Slot`.
Handy for testing sync on one machine with a local server (`npm start` in `server/`).

---

## Repository layout
```
client/                 the FL side (C, Win32)
  launcher/flim.c       flim.exe: setup window, starts FL, loads the engine into it
  engine/flim_engine.c  the engine: edit detection, applying edits, locks, pattern ops, sample transfer,
                        networking, toolbar UI (status + who is where)
  common/               settings (flim.ini) and resource IDs shared by both;
                        flim_notes_crdt.h = note merging, by cashflowbeatz
  build.bat             build script (MSVC)
  restart_test.ps1      dev loop: rebuild and start two connected FLs
  dev/                  reverse-engineering and test tools (not built or shipped)
server/                 flim-server (Node.js + TypeScript, WebSocket + HTTP)
  src/                  server.ts (connections, slots, limits), session.ts (ordering, locks), protocol.ts,
                        blobs.ts (sample file store)
  Dockerfile            container image
```

## Troubleshooting
- **"This FL Studio is version X. flim supports these builds: ..."**: your FL build isn't supported yet.
  See [Other FL Studio builds](#other-fl-studio-builds).
- **"Can't connect: server not found"** or **"nothing answers at that address"**: check the address, that
  the server is running, and (over the internet) that the port is forwarded.
- **"Can't connect: secure connection failed"**: you typed a bare host name or `wss://`, but the server
  speaks plain WebSocket. Use `ws://host:8080`.
- **"Can't connect: not a flim server (HTTP …)"**: something answered at that address, but it isn't
  flim-server.
- **"Wrong session password"** / **"Session not found"**: ask the host for the link and password again;
  the session may have ended (host left, or 5 minutes without activity).
- **"All sessions are in use"**: the server's session(s) are taken. Try again later.
- **"Server password needed"**: the server has `FLIM_PASSWORD` set. Ctrl+click **Host** and enter it.
- **"Everyone in a session needs the same FL Studio build"**: the host's FL build differs from yours.
  See [Other FL Studio builds](#other-fl-studio-builds).
- **Something didn't sync or FL crashed**: please open an issue and attach `%TEMP%\flim_engine.log`.

---

## Other FL Studio builds

flim calls FL Studio's internal functions, and where those sit inside FL changes with every FL
update. So flim keeps a table for each FL build it knows. Check yours under **Help → About**.

| Build | Status |
|---|---|
| **25.2.3.5171** | The main build. Everything is tested on it. |
| **25.1.6.4997** | Works: the automated feature test passes, as on 25.2.3.5171 (knobs, mixer, channels and their order, plugins, patterns and pattern operations, notes, playlist clips, markers, time signatures, sample transfer). |

**Everyone in a session needs the same build.** FL Studio can't safely load projects and plugin
states from a newer FL, and both travel in a session. So if the host's build differs from yours,
flim doesn't load the host's project: it tells you and leaves the session.

**Your build isn't listed?** `flim.exe` tells you when it starts. If you start FL anyway, flim stays
off and FL runs as usual: nothing breaks, it just doesn't sync. What you can do:
1. **Ask for it:** [open an issue](../../issues) with your exact build number (Help → About). Adding
   a build means mapping flim's table onto it and testing it, which is mostly automated.
2. **Add it yourself:** the tools in `client/dev/` map the table from 25.2.3.5171 onto another build
   and test the result. See "Adding an FL build" in [client/dev/README.md](client/dev/README.md).
3. **Use 25.2.3.5171** if you have it installed.

---

## Credits

- **[cashflowbeatz](https://github.com/cashflowbeatz)**: **Rooms** (the flimrooms app, its relay and
  its flim engine, all his) and the **note merging** behind the host's *Merge* option
  (`client/common/flim_notes_crdt.h`, used unchanged). Both come from his
  [pull request #1](../../pull/1). Thank you!

---

*FL Studio is a trademark of Image-Line. This project contains no FL Studio code or files. It only talks
to an FL Studio installation that you already have.*
