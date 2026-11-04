# Testing and verification

## Recorded 0.2.27 local results

246 desktop tests, 33 native harnesses, 19 native HTTP checks, 18 file-sync/status checks,
195 UI checks and 76 Worker tests pass. The native workflow harness exercises confirmed channel
adds/deletes, stale targets, reorder bounds, no-op orders, selection recovery and stale hashes.
The HTTP fixture verifies upload write exclusion, source length, conflict retry and per-file
retry progress. Actual Electron WebRTC passes with five direct downloads across three isolated
sessions against the local Cloudflare emulator. Folder/window/sidebar/zoom/recovery checks pass.

[All 57 changes](releases/0.2.27.md) and [0.2.27 QA](../client/desktop/QA-0.2.27.md) separate
synthetic fixtures from physical FL/MIDI coverage. No new FL profile or deployed-relay check.
The earlier intermittent FL24 recovery-save stall remains unresolved.

## Recorded 0.2.26 local results

224 desktop tests, 32 native harnesses (including nine synthetic host/member combinations),
13 native HTTP checks, 18 file-sync/status checks, 195 UI checks and 76 local Worker tests pass.
The three-session Electron WebRTC fixture transfers a 2,097,171-byte file five times directly
with two concurrent requests, recovers its hidden worker, tries an alternate source and serves
a verified received copy after the original file companion stops. Its one forced R2 fallback
causes exactly one R2 read. Folder/window/sidebar/zoom/recovery checks also pass.

[0.2.26 QA](../client/desktop/QA-0.2.26.md) records final artifact checks and limits. This pass
is local only; it does not run a new deployed-relay or physical FL/MIDI test. The historical
results below retain the scope of their own release.

## Recorded 0.2.25 results

| Check | Recorded result | What it establishes |
| --- | --- | --- |
| Native harnesses | 32 executable suites passed | Parsing/setter guards, native content verification, complete snapshots, note/clip/plugin handling, bounded queues and format adapters using synthetic native fixtures. |
| Mixed FL host/member paths | Nine synthetic combinations passed | Negotiated FL24/25/26 shared note/control routing in each direction, not nine new live sessions. |
| Desktop backend | 193 tests passed | Room/launch validation, settings/folders, diagnostics, recovery, direct-file broker and transfer-status handling. |
| Room and Files UI | 127 + 68 checks passed | Real renderer controls against fixture bridges, keyboard/focus, state/error/zoom/sidebar behavior. |
| Cloudflare Worker | 76 local tests passed | Miniflare executes room/file admission, ordering, locks, quotas, integrity, capability isolation/revocation and cleanup. |
| Actual Electron WebRTC | Passed against emulator and deployed Cloudflare | Three 2,097,171-byte direct downloads per run, two concurrent, source/peer failure, authentication and one R2 fallback read. Two isolated launch sessions on one computer. |
| Native sample loopback | 1 stored upload, 13 downloads across failure/retry cases | Actual WinHTTP workers, inbound path rewriting, cancellation, verified content and untouched source audio. |
| Electron/package checks | Passed | Folder-picker IPC/persistence, fitted windows, recovery, icons, portable/unpacked startup and native-byte equality. |

[0.2.25 QA](../client/desktop/QA-0.2.25.md) and [all 34 fixes from 0.2.24](../client/desktop/QA-0.2.24.md)
describe the exact cases.
Versioned reports under `client/desktop/QA-*.md` retain their original dates/status; “local only”
in an older report describes that test run, not the later GitHub publication. Personal paths and
process observations are omitted from published evidence. Raw logs/screenshots stay local.

## Reproduce the checks

See [build prerequisites](BUILDING.md). From `client/desktop`:

```powershell
npm test
npx install-electron
npm run build
node test/ui.cjs
$env:FLIM_FILES_TEST_DIST = 'dist'
node test/file-sidebar-ui.cjs
```

UI scripts currently expect Brave at its normal Windows installation path. Electron window,
folder, recovery and package scripts run **sequentially** in isolated profiles:

```powershell
node test/sample-location-window.cjs
node test/window.cjs
node test/sidebar-window.cjs
node test/recovery.cjs
node test/package.cjs
node test/portable.cjs
```

Package checks expect the local reviewed FL24/25/26 installations and a built portable/unpacked
app. They inspect/discover installations but do not allocate a room or start FL. They are not
suitable for a generic CI runner with no FL installations.

Build native harnesses with `cmd /c client\dev\harness\build.bat` from the root. Execute the
33 deterministic harnesses listed in the CI workflow. Transfer harnesses require their loopback
orchestrators rather than being run directly:

```powershell
Set-Location client/dev
cmd /c harness\build-file-sync.bat
node file_sync_test.cjs
node transfer_test.cjs
```

Run `npm ci` and `npm test` in `server/cloudflare` for the Worker, and in `server` for the retained
Node.js relay. Both test locally. CI runs deterministic native/desktop/relay suites without an
Image-Line account or live FL instance. Hosted CI results appear on the PR after pushing.

For actual WebRTC bytes, install/build `server/cloudflare` first, then run `npm run test:peer`
from `client/desktop`. It creates a local emulator and isolated Electron launch sessions.
The optional live mode requires the relay owner's existing private key file; it is not run in
CI. See the test source and [direct-file evidence](PEER-FILES.md).

## What still needs live testing

Earlier owned scratch FL sessions and their limitations are recorded in
[0.2.11 QA](../client/desktop/QA-0.2.11.md) and the
[compatibility evidence index](../client/dev/compatibility/README.md). The latest pass did not
repeat physical MIDI, two-computer, live vendor-version or drag/drop sessions. The earlier FL24
recovery-save stall remains an unresolved observation. Broad plugin matrices, extended internet
soak/load, audio-render equivalence and arbitrary FL patches are not established.

For a friend test, use disposable projects, record exact builds/host direction, compare notes
in both directions, then verify one small sample. Check actual playback as well as room status.
Do not run native runtime probes against an unrelated or unsaved user session.
