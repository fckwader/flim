# flim 0.2.26: local transfer recovery verification

Validated locally on 2026-11-01 from source baseline `2555c89`. This working tree is uncommitted.
The [35 changes explained](../../docs/releases/0.2.26.md) cover direct-file recovery, bounded
background work, onward serving of verified samples and local request validation.

## Recorded checks

| Check | Result | Scope |
| --- | --- | --- |
| Desktop backend | 224 passed | Existing 193 plus 31 broker, WebRTC-worker and Electron-adapter regressions. Includes cancellation, stale messages, IPC cleanup, failed loading, buffer draining, early ICE, content bounds and retries. |
| Actual Electron WebRTC | Passed against local Cloudflare emulator | Three isolated launch sessions; five exact 2,097,171-byte direct downloads, two concurrent; a worker crash, changed first source, alternate source, onward serving after the original file companion stops and one forced R2 read. |
| Native harnesses | 32 executables passed | Includes nine synthetic FL24/25/26 host/member combinations and the existing note, clip, plugin, snapshot, queue and content regressions. |
| Native WinHTTP loopback | 13 named checks passed | Real HTTP registration deduplication/reconnection, verified direct bytes, corrupt/missing/throttled direct fallback, R2 pause isolation, progress and legacy welcome. |
| Native file-sync loopback | 18 named checks passed | Includes the status parser, verified received-file registration, unchanged-cache reuse, inbound path rewriting, automatic outage recovery, local disk errors, quota behavior and untouched source audio. |
| Cloudflare emulator | 76 passed | Existing room/file admission, ordering, locks, quotas, integrity, isolation, revocation and companion cleanup. Worker source is unchanged. |
| Room/UI and Files/UI | 127 + 68 passed | Retained controls, compact layouts, dropdown/sidebar navigation, keyboard/focus, errors and reduced motion. |
| Real Electron | Passed | Folder dialog/persistence, compact fitted window, mode switching, sidebar geometry, 200% zoom and bounded controls recovery. |
| Final package and portable startup | Passed | Bundled worker, preload, main, runtime, frontend and native bytes match their sources. Reviewed FL24/25/26 discovery, icons, diagnostics and isolated portable/unpacked startup pass without starting FL. |

The new missing-source timer test failed before its correction and passed afterward. It found
that switching to a short closing timer left the earlier 120-second timer scheduled. The final
desktop suite includes this regression.

The actual Electron integration fixture checks the shared file service, not FL's own MIDI or
project application. Native loopbacks separately execute the real transfer, verification and
path-rewrite code. Test capabilities and temporary paths remain excluded from Git.

Local artifact: [flim-rooms-0.2.26-win64.exe](release/flim-rooms-0.2.26-win64.exe),
103,587,012 bytes. SHA-256:
`5f9f6d2a732e4b6c3f570e2f6b850bdab7dfb5cc401df05e723613c1609c7d13`.
[Machine-readable report](../dev/compatibility/desktop-0.2.26-2026-11-01.json).

## Compatibility and limits

Reviewed builds remain **FL24 24.2.2.4597, FL25 25.2.5.5319 and FL26 26.1.7.5654** with exact
fingerprints. FL24 remains supported. Profiles, note CRDT semantics, plugin isolation and the
older receiver's notes/basic-controls fallback are unchanged. Unsupported sounds/features still
remain unavailable; this does not convert newer complete projects into an older FL format.

This pass did not operate any user FL process, project, installation or licensing state. It did
not establish physical MIDI behavior, two physical computers, remote NAT traversal, every VST
state version, every FL patch or a long internet soak. The earlier intermittent FL24 recovery-save
stall remains unresolved. An actual native fault can pause sharing while leaving FL open.

Onward file serving does not transfer room ownership. The host's native departure still ends
the room. Initial R2 uploads, configured R2 usage guards and the absence of TURN remain in place.
Cloudflare still coordinates edits and permissions; a complete session is not end-to-end encrypted.
No GitHub commit, push, PR, release or Cloudflare deployment was made in this pass.

## Retained design

No frontend, CSS, artwork, palette, typography, navigation or layout source changed. The existing
equipment-card direction and ENERGY 1 / RHYTHM 1 / MOTION 2 remain. Current renderer and real
Electron checks cover the retained UI. Release copy lists concrete changes and separates fixtures
from live coverage; no universal compatibility, latency or zero-bug guarantee is made.
