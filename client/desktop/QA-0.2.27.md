# flim 0.2.27: channel and sample workflow verification

Validated locally on 2026-11-03 from committed baseline `2555c89`, with the earlier local
0.2.26 work retained. The working tree was uncommitted during validation. The [57 changes explained](../../docs/releases/0.2.27.md)
cover channel mutations, sample metadata, stable uploads, direct-file recovery and room launch.

## Recorded checks

| Check | Result | Scope |
| --- | --- | --- |
| Desktop backend | 246 passed | Previous 224 plus 22 regressions covering optional launch failures, expired reservations, payload refresh, installation-scan races, Unicode, source replacement, signaling, cleanup and later-source timing. |
| Native harnesses | 33 executables passed | Includes the new channel workflow harness, plus existing note CRDT, clip, plugin, metadata, snapshot, queue and nine synthetic FL24/25/26 host/member combinations. |
| Native WinHTTP loopback | 19 named checks passed | Actual HTTP with source write exclusion, exact upload length, conflict retry, retry progress, formatted/empty operation objects, invalid metadata, native peer registration, direct verification and fallback. |
| Native file-sync/status loopback | 18 named checks passed | Actual inbound path rewriting, verified cache reuse, automatic pending recovery, corrupt content, disk errors, quota isolation and untouched source audio. |
| Actual Electron WebRTC | Passed against local Cloudflare emulator | Three isolated sessions; five exact 2,097,171-byte direct downloads, two concurrent; worker crash recovery, changed first source, alternate source, onward serving and one forced R2 read. |
| Cloudflare emulator | 76 passed | Existing room/file admission, nine version combinations, ordering, locks, quotas, integrity, isolation, revocation and cleanup. Worker source is unchanged. |
| Room/UI and Files/UI | 127 + 68 passed | Retained compact UI, sidebar, dropdown, keyboard/focus, errors, reduced motion, zoom and bounds. No frontend source changed. |
| Real Electron | Passed | Folder dialog/persistence, compact window/mode switching, sidebar geometry/focus, 200% zoom and bounded renderer recovery. |
| Production build | Passed | TypeScript, Vite, native launcher/engine and portable packaging. |
| Package and portable startup | Passed | Source/native byte equality, bundled file worker, production isolation, reviewed FL24/25/26 discovery, icons, local diagnostics and clean initial room state. No FL launched. |
| Diff whitespace check | Passed | `git diff --check`. |

The native workflow test originally exposed missing resolver and note-lock setup in its
synthetic fixture. Those fixture omissions were corrected before the successful final run.
The result does not establish live FL behavior. Real HTTP and actual Electron tests separately
exercise file bytes and connection recovery without operating a user FL session.

## Local artifact

[flim-rooms-0.2.27-win64.exe](release/flim-rooms-0.2.27-win64.exe), **103,587,987 bytes**.

SHA-256: `d98c6554928528743c060001d08896d04805b9f991747e01b435efbcdfc14202`.

Bundled native launcher:
`4e098c180294b29e56333b2f7f7ace2d1a8e55f52123b7fe1e3125b3ef18c9db`.

Bundled native engine:
`d06c112d0e8d652a58c11e99aa6f8e2a026155ac9ce1a7b0d92e59f0e7205b37`.

[Machine-readable verification](../dev/compatibility/desktop-0.2.27-2026-11-03.json).

## Compatibility and remaining limits

Reviewed builds remain **FL24 24.2.2.4597, FL25 25.2.5.5319 and FL26 26.1.7.5654** with exact
fingerprints. FL24 remains supported. This pass adds no build profile or binary-address map.
A different FL patch still requires a reviewed profile; this is not universal version support.

The fixes protect shared channel indices and file work used by all three reviewed profiles.
Recorded notes retain their existing CRDT semantics. Missing plugins remain isolated, and an
older receiver retains the existing shared-note/basic-control fallback for unsupported newer
project content. These paths do not convert a newer complete project into an older FL format.

No user FL process, project, installation or licensing state was operated. Physical MIDI,
two physical computers, remote NAT traversal, all VST state versions and a long internet soak
were not established. The earlier intermittent FL24 recovery-save stall remains unresolved.
A native fault or unreproducible channel mutation can pause sharing while leaving FL open.

The host's native departure still ends the room. R2 uploads, R2 safety guards and automatic
fallback remain in place. No TURN service was added. WebRTC file channels encrypt their traffic,
while room edits and R2 backups still trust the relay.

## Retained design and publication status

No renderer, CSS, artwork, palette, typography, navigation or layout source changed. The
equipment-card direction and ENERGY 1 / RHYTHM 1 / MOTION 2 remain. Current UI and real Electron
checks cover the retained interface. Release copy describes actual checks without a latency,
universal-compatibility or zero-bug guarantee.

These checks ran locally before the subsequent GitHub review publication. The machine-readable
record retains that validation-time status. Publishing the review branch does not deploy Cloudflare
or publish a new executable release.
