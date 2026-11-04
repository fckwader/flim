# What changed in this fork

These changes support reviewed FL Studio 24/25/26 builds and improve shared projects, edit ownership and sample transfers. Historical entries retain the status of their own builds.

In this document, **client** means the flim program running with your FL Studio. **Server** means the program that passes edits and sample files between you and your friends. An **edit lock** is a temporary reservation that stops two people from changing the same control at the same time. A **cache** is temporary file storage that can be cleared to make room.

## Version 0.2.27: safer channels and browser-sample sharing (2026-11-03)

57 additional fixes and safeguards confirm FL's channel adds/deletes before changing shared
indices, preserve selection after interrupted moves, validate preset sample metadata and keep
upload sources stable. Direct files get better source timing and recovery; optional file-service
errors cannot overturn a confirmed FL launch. Installation scans, cancellation, Files status and
error reporting receive further checks. Includes the earlier local 0.2.26 work.
[All 57 changes explained](docs/releases/0.2.27.md) · [QA](client/desktop/QA-0.2.27.md).
Reviewed builds remain 24.2.2.4597, 25.2.5.5319 and 26.1.7.5654. Validation ran locally before
GitHub review. No Cloudflare deployment is included in this contribution.

## Version 0.2.26: recover direct files and reuse verified samples (local, 2026-11-01)

35 additional improvements fix next-source retry cancellation, abandoned serving slots, stale
worker commands, connection setup ordering, blocked send buffers, incomplete content and timer
cleanup. Verified recipients can serve samples onward, unchanged files avoid repeated registration,
and a busy local peer cannot trigger a cloud quota pause. Exact FL24/25/26 checks and the compact
UI remain in place. [All 35 improvements](docs/releases/0.2.26.md) · [QA](client/desktop/QA-0.2.26.md).
This build stays local; no GitHub publication or Cloudflare deployment.

## Version 0.2.25: direct samples with Cloudflare coordination (2026-10-28)

WebRTC transfers referenced samples directly when connected peers are available. Cloudflare
keeps room authentication, ordered edits and locks; recorded notes retain their CRDT. Initial
R2 uploads stay in place and failed direct transfers use the verified backup automatically.
The app keeps its file service alive while launched FL processes run, bounds concurrent work,
revokes departed capabilities and preserves exact FL24/25/26 checks. Includes all 0.2.24 fixes.
[21 changes explained](docs/releases/0.2.25.md) · [QA](client/desktop/QA-0.2.25.md).

193 desktop tests, 32 native harnesses, 195 UI checks, 76 local Worker tests, actual Electron
WebRTC bytes through local and deployed signaling, native loopbacks and package/portable checks
pass. No fresh two-computer FL/MIDI test or new FL profile. Full sessions still trust the relay.

## Version 0.2.24: complete note snapshots and verified sample transfers (local validation, 2026-10-28)

34 additional fixes share larger multi-pattern edits, prepare full note snapshots before queuing,
ignore harmless note order changes, avoid unchanged CRDT/playlist application and verify actual
native note/clip contents. Playlist matching uses sorted records. FL24 control snapshots reserve
space only for meaningful work. Sample handling validates path/size identities, bounds downloaded
bodies, separates concurrent progress, corrects retry totals and cancels obsolete hashes. Received
folder validation and storage messages cover Windows devices, Unicode, full disks and missing
drives. [Detailed fixes, evidence and compatibility limits](client/desktop/QA-0.2.24.md).

32 native harnesses, 180 desktop tests, 195 UI checks, real Electron window/recovery checks,
73 local worker tests and native file-transfer loopbacks pass. Reviewed build profiles remain
FL24 24.2.2.4597, FL25 25.2.5.5319 and FL26 26.1.7.5654. No fresh two-computer/MIDI proof,
new FL build profile, commit, push or Cloudflare deployment.

## Version 0.2.23: native editing and mixed-build reliability (local, 2026-10-28)

39 additional fixes retain queued preset source versions, structurally dispatch formatted
messages, validate whole control snapshots, skip unsupported FL24 mixer tracks, coalesce repeated
control updates and yield between apply batches. Names, details and locks validate before native
calls; metadata exceptions and silent note/clip add refusals do not confirm failed sync. CRDT
joins/captures allocate less memory while retaining tombstones. Stable-ID VST matching recognizes
equivalent Windows paths. [Detailed changes and QA](client/desktop/QA-0.2.23.md).
31 native harnesses, nine synthetic host/member combinations, 177 desktop tests, 195 UI checks,
73 local worker tests and native transfer loopbacks pass. The complete portable app was rebuilt
and package/startup checks passed. No new FL profile, live two-computer/MIDI proof, commit, push
or Cloudflare deployment.

## Version 0.2.22: recover controls, preserve pending activity and refine Files (local, 2026-10-28)

35 additional improvements make settings saves withstand brief Windows locks, recover setup
after controls reload during a main-process operation, back off repeated status failures and
respect Retry-After. Files gains incoming/outgoing filters, room-wide find shortcuts, truthful
limited-list warnings and better folder progress/focus behavior. Both desktop aggregation and
native status retention prioritize unfinished work. Native ready entries publish full progress
immediately; failed status replacement removes its scratch file. The complete executable
includes the rebuilt native engine. [Detailed fixes and QA](client/desktop/QA-0.2.22.md).
No commit, push or Cloudflare deployment. Exact FL profiles and relay behavior are unchanged.

## Version 0.2.21: choose received-file storage and recover from local disk failures (local, 2026-10-28)

40 improvements add a saved destination picker inside Files, use redirected Windows Documents,
validate actual writable storage, preserve the previous choice on failed saves, and bind each
new FL process to its own destination. Existing files stay put. Missing custom drives cannot
silently redirect downloads. Local folder/write/flush/locked-target errors retain shared edits
for automatic retry while the room remains connected. Downloads use unique temporary names,
flush before installation, and normalize long/reserved Windows filenames. Closed rooms stop
automatic Files reads without discarding confirmed activity; grouping/search do less repeated
work, and a window-fit failure no longer breaks controls. [Detailed fixes and QA](client/desktop/QA-0.2.21.md).
No GitHub push, commit or Cloudflare deployment. Reviewed FL profiles and relay behavior are unchanged.

## Version 0.2.20: verified status reads and recoverable desktop setup (local, 2026-10-28)

40 reliability improvements reduce repeated file-body reads, preserve each process's confirmed
sample activity, detect incomplete/replaced status files, and prevent old setup/read completions
from changing a newer room. Relay and launcher data receive stricter validation. Reservations
are checked again immediately before launch. Member preflight updates the people list, polling
uses completion times, and same-count participant changes are logged without recording names.
Settings failures explain recovery while retaining usable folder choices. Failed setup can retry,
logs stay available during setup failure, and the recovery screen tolerates fitting failures,
duplicate log clicks and content resizing. Diagnostics use atomic metadata and bounded Unicode text.
[All 40 changes and verification](client/desktop/QA-0.2.20.md). Native engine/profile behavior and
Cloudflare/R2 deployment remain unchanged. Nothing was pushed to GitHub.

## Version 0.2.19: saved Files views, truthful status and simpler navigation (local, 2026-10-28)

37 new desktop refinements preserve Files search/filter/order/scroll and confirmed activity,
add search-aware filter/group counts and optional recent ordering, reduce repeated help,
and keep diagnostics accessible with the sidebar open. Offline/stale/closed room indicators
agree across the badge, collapsed card and title. Copy remains usable during other room work;
disabled setup explains its cause; input, details and Windows picker keyboard handling improve.
[Detailed changes and QA](client/desktop/QA-0.2.19.md). Native/relay behavior is unchanged.
Nothing was pushed to GitHub or deployed to Cloudflare.

## Version 0.2.18: Files navigation, reliable status and input refinements (local, 2026-10-27)

Files gains local filename search, keyboard-operated status filters, visible/total counts,
separate waiting counts, completed/total byte progress, direction labels and manual refresh.
Read failures back off and preserve confirmed rows; one unreadable FL process no longer freezes
other processes' status. Hidden and closed views stop automatic checks, and closing a room
retains its confirmed file activity. Automatic reads keep the Refresh label still.
Delayed paste cannot take focus back from a newer field selection. Composing text cannot
accidentally submit a room or operate its picker. Picker previews scroll only their list,
participant overflow is measured, narrow names use one column, and dismissible errors remain
visible with Files open. [Detailed changes and QA](client/desktop/QA-0.2.18.md).
Native/relay behavior is unchanged. Nothing was pushed to GitHub or deployed to Cloudflare.

## Version 0.2.17: visible sidebar arrow and stable room menu (local, 2026-10-27)

The Files arrow is visible at the card's upper right before entering a room and stays available
throughout setup and room use. It opens a real lateral sidebar. The initial empty view explains
sample sharing and opens setup without reading transfers from an earlier room. One Back action
and the arrow replace duplicate navigation. Create/Join now holds its fields and action button
in place. Immediate focus after switching preserves the first keystroke; closing Files restores
focus before the next paint. Width changes no longer briefly collapse the window, and initial
placement leaves room for setup to grow downward. [Detailed changes and QA](client/desktop/QA-0.2.17.md).
Native/relay behavior is unchanged. Nothing was pushed to GitHub or deployed to Cloudflare.

## Version 0.2.16: compact app and automatic sample recovery (local, 2026-10-27)

Files is a lateral sidebar beside the room, with a horizontal reveal and reduced-motion support.
The app is 400px wide normally and 680px with Files open; native window controls share its header.
The component uses React directly instead of the imported card runtime. Recoverable sample
failures keep the original channel/project edit pending and retry in the native workers. Files
shows that waiting state. Verified bytes receive a local path before the edit is released, and
session changes cancel old pending work. [Detailed fixes and QA](client/desktop/QA-0.2.16.md).
No fresh cross-computer FL/MIDI test, GitHub push or Cloudflare deployment is claimed.

## Version 0.2.15: softer controls and supported FL24 (local, 2026-10-27)

The supplied card/dropdown references are adapted to the existing anonymous room app. Inputs
have no dark perimeter; blue bottom edges show keyboard focus. The FL family picker has padded
choices, a selection check, keyboard preview/selection, type-ahead and predictable dismissal.
Create/Join uses a compact soft switch. The tested FL24.2.2.4597 engine is supported without
an experimental opt-in, while exact fingerprint checks remain. [Details and QA](client/desktop/QA-0.2.15.md).
Nothing was pushed to GitHub or deployed to Cloudflare.

## Version 0.2.14: 37 interface and stability refinements (local, 2026-10-27)

[The new numbered change list](client/desktop/QA-0.2.14.md) describes each change and its limits.
Menu, redundant card framing, participant circles/dividers and red input outlines are removed.
Room tabs, normal paste, focus ownership and restored busy state are corrected. Renderer crashes
recover within a fixed budget without quitting the main process. Read-only status and sample
checks retry temporary failures; sample lookup failures no longer stop the entire session.
The rebuilt native engine retains quota, compatibility and project-preservation protections.
No GitHub write or Cloudflare deployment occurred.

## Version 0.2.13: 40 desktop fixes and refinements (local, 2026-10-27)

[The numbered change list and QA](client/desktop/QA-0.2.13.md) explain all 40 changes in plain
language. This update adds setup retry, inline validation, deliberate clipboard paste, safe
clipboard feedback, installation rescanning, offline notices, fresh manual status requests,
status-reply invalidation, people-list freshness, compact full-room scrolling, easier Menu
navigation, version visibility, high-contrast/narrow layouts and a recoverable renderer error
screen. Copying an invitation no longer interrupts an in-flight people lookup.

The native engine, launcher, exact FL profiles and Cloudflare deployment are unchanged. Existing
FL/MIDI runtime limits remain; this is not evidence that every FL patch works. The complete
0.2.13 portable app remains local, with no GitHub write or relay deployment.

## Version 0.2.12: compact room component and status-only FL toolbar (2026-10-27)

- Remove Host, Connect and Disconnect buttons from flim's FL toolbar. Create/join rooms in the
  desktop app. FL retains connection status, people/focus information and unavailable-sound hints.
  Clicking the status cannot accidentally open a connection dialog or end sharing.
- Fit the desktop app around a 456px white component, removing the gray canvas and extra outer
  footer. The closed artwork remains. Opening setup gives the controls the space previously used
  by the artwork. Back sits above the form; local test logs are under the header Menu.
- Keep keyboard focus when navigating back. Escape dismisses the tools menu and restores its
  trigger; clicking or tabbing outside closes it without leaving the room. The window follows
  content height and still supports scrolling on small monitors and at 200% zoom.
- Let native connection status use the space freed by the buttons. On narrow FL toolbar gaps,
  hide the version text first, then hide an unusably small bar instead of covering FL's controls.
  Expose connection text through the native window title as well as painting it.
- Fix a mixed-version plugin recovery edge case: identical preset bytes could keep an older
  rejection record even when their authenticated source was newer. Update the retained origin
  and mark those bytes unavailable to the older loader, without stopping other shared edits.
- Preserve exact engine profiles and the automatic any-supported-host fallback. Unknown FL patches
  remain unverified; unsupported sounds and playlist features stay unavailable on older members.
  Native faults still stop sharing to protect the project.

[0.2.12 QA](client/desktop/QA-0.2.12.md) records the new native, UI and package checks. Existing
user FL24 was left open, so the earlier 0.2.11 live tests remain separate. No GitHub write or relay
deployment is part of this app update.

## Relay update: remove the daily room creation limit (2026-10-27)

- Remove the shared twenty-new-rooms-per-day cutoff for app rooms and legacy hosting. Existing
  exhausted counters no longer block creating another room, so testing can resume immediately
  after the relay update without waiting for midnight or installing a new desktop app.
- Replace the separate daily creation-request caps with a short burst guard: ten requests per
  IP and sixty across the relay per UTC minute. Other request protections, four simultaneous
  rooms, eight people per room, and all R2 storage and transfer cutoffs remain.
- Check creation past twenty rooms, existing exhausted counters after restart, legacy hosting,
  burst throttling/recovery, room isolation and the existing R2 protections in local Worker tests.

All 73 Worker tests and 11 public room checks passed. Worker
`e8f907ea-69eb-4fcb-84aa-b303d3126c26` is deployed with 100% traffic at the existing relay.
The public check created two rooms and verified joining, isolated edits and host-departure cleanup.
R2 limits were read back unchanged. [Deployment evidence](client/dev/compatibility/relay-room-limits-2026-10-27.json).
No desktop repackaging or GitHub write was needed.

## Version 0.2.11: automatic recovery and any supported host (2026-10-27)

- FL24 no longer has to host an FL24/25/26 group. If an older FL joins a newer host, flim
  automatically prepares shared note channels and basic controls. It keeps newer project files
  and preset bytes out of the older loader. Unsupported sounds and playlist features stay
  unavailable instead of blocking the room. This is not a project-format conversion.
- Before preparing that workspace, flim saves the local project in `Documents\flim\recovery`
  and works from a separate session copy. A failed backup stops the operation before clearing
  channels. The original project path is not used for subsequent session saves.
- Notes already in the host's project, later recorded notes, moves, deletions, names and basic
  channel/mixer controls travel both ways. The initial fallback also receives mixer names,
  colors and routing. Empty pattern baselines no longer create hundreds of native patterns or
  repaint each one, removing a delay observed in the first FL26-to-FL25 live test.
- Missing/rejected plugins recover automatically after their matching installation or scan
  records change. An unchanged rejected preset is not repeatedly loaded. Scanned stable VST
  identities still select the local path; having the same display name alone is insufficient.
- Hosting, sample uploads within relay limits, and routine notices no longer require an OK,
  Yes or Retry click. The native hosting dialog race is fixed. Connection errors remain visible
  in the status and local logs. Genuine native faults still stop sharing to protect the project.
- Targeted joining snapshots reach only the intended participant, including when stored in R2.
  A new joiner cannot reset existing participants. Retained presets preserve their original FL
  version even when relayed later by an older host. Older members cannot overwrite the host's
  complete playlist with their limited local workspace.
- The updated Cloudflare Worker negotiates portable sync and the existing note CRDT. Existing
  rooms keep their negotiated mode. The CRDT merges note additions/deletions; it does not merge
  whole plugin/project files or stream unrecorded keyboard audio.

Exact checks, tested builds, artifact fingerprints and deployment status are in
[QA-0.2.11](client/desktop/QA-0.2.11.md). GitHub remains unchanged. Earlier entries below describe
the behavior and limits of their own versions.

## Version 0.2.10: isolate unavailable plugins and resolve local VST paths (2026-10-27)

- A missing external plugin identified by FL's scanned plugin database, or a preset that FL
  rejects normally, no longer ends the room. flim keeps the received preset and isolates that
  plugin's controls. Piano-roll notes, channel volume/pan and other available plugins continue
  through their existing shared-edit paths. A native memory fault still stops sharing safely.
- Match VST2 unique IDs and VST3 class IDs rather than requiring identical version labels or
  installation folders. For an unambiguous scanned installation, change only the local path
  in the loading copy. Keep the original shared preset, plugin identity and sound data intact.
  The installed plugin still decides whether it supports the received state. VST2 and VST3,
  or different plugin IDs, are not substituted automatically.
- The FL toolbar shows how many plugins are unavailable. Click its status text for the list
  and Retry after installing/updating the plugin and running FL's plugin scan. Enter/Space
  on the focused toolbar and the Windows context-menu action open the same dialog.
- Avoid repeat loads of an unchanged rejected preset and skip its background save sweeps.
  Cache scanned plugin metadata until Retry; allocate the catalog in bounded blocks rather
  than copying it for each entry. Ambiguous scanned binaries are reported, not guessed.
- Keep unavailable presets attached to channels through reorder/deletion. Retain and coalesce
  received control values without applying them to the wrong plugin; replay them after recovery.
  A host's retained missing-plugin states and controls accompany snapshots for late joiners.
- In mixed-build rooms, a newer member's incompatible preset edit is restored to the agreed
  preset without ending the room. The relay's existing oldest-host and channel/project-format
  safeguards remain. Adding a channel that an older host cannot represent still needs that host.
- Keep the working 0.2.9 portable app and native payload available alongside this update.

This improves plugin handling on mapped engines; it does not establish every FL patch or VST
version as compatible. Project opening and hardware MIDI across all builds still need real
two-computer tests. Detailed checks and limitations are in [QA-0.2.10](client/desktop/QA-0.2.10.md).
The Worker remains undeployed and GitHub has not been changed.

## Version 0.2.9: fix FL opening without joining the room (2026-10-27)

Your 0.2.8 logs showed that FL opened, but flim stopped before trying to connect. A normal
FL26 launch reproduced Windows error 126 on both message hooks. These hooks let flim process
shared edits on FL's main thread. Windows was asked to resolve flim's DLL module again even
though the callbacks were already inside the process.

- Use the existing callbacks for hooks within the same process. FL now finishes flim startup
  and connects to the Cloudflare relay.
- Wait for FL's actual main form instead of selecting the first visible window, which could
  be the early `TApplication` window. Recheck that it still belongs to this process before
  installing thread-specific hooks.
- Require both hooks. If either fails, remove the other and record the Windows error rather
  than leaving partial startup behind. Missing main forms have a bounded wait and a diagnostic.
- Preserve 0.2.8 and provide a separately named 0.2.9 portable app so testers can identify the fix.

Live startup checks connected the installed FL24.2.2.4597, FL25.2.5.5319 and FL26.1.7.5654
as hosts to the existing Cloudflare relay. These confirm startup and room admission; they do
not establish every shared-edit feature, hardware MIDI or arbitrary patch-build compatibility.
The Worker was not changed or deployed, and CRDT activation remains pending deployment.
Detailed evidence is in [QA-0.2.9](client/desktop/QA-0.2.9.md).

## Version 0.2.8: smaller window and concurrent piano-roll editing (local, 2026-10-27)

- The desktop window fits the room card. Opening the menu grows the window; closing it shrinks
  the window. It stays within the monitor's usable area. Larger text scales the window, and
  long menus remain scrollable. This also fixes zoom changes that leave the card's height unchanged.
- Incoming notes keep unchanged notes in FL's own array. A single new note no longer removes
  and rebuilds the whole pattern. Existing selections stay local, including stacked identical
  notes; duplicate deliveries avoid unnecessary editor redraws.
- Recorded MIDI changes use a shorter batching interval: a 100 ms scan, a 100 ms quiet period,
  or a 200 ms maximum batching interval during continuous recording. Network time and FL's main
  thread add to that delay. This does not transmit unrecorded key presses or stream audio.
- The local client and relay implement a CRDT for piano-roll notes. Each added note has an
  immutable identity. A delete records which identities were observed, so a delayed copy cannot
  bring a deleted note back. Independent additions and deletes merge instead of reserving the
  entire pattern. Pending local recording is captured before applying someone else's delta.
- Identical overlapping notes remain distinct. A move or velocity change removes the old note
  and adds a new identity. If two people move the same note simultaneously, both new versions can
  remain; this merge rule does not choose one person's version silently.
- The new note mode requires an explicit relay handshake. Older clients cannot enter a CRDT
  room; a new client joining an older room uses its existing locked snapshots. Malformed data,
  conflicting immutable identities, different delta baselines and exhausted history stop sharing
  with a diagnostic. The bounds are 16,384 history entries per pattern and 262,144 per client.
  Removed identities count toward those bounds. Starting a fresh room resets the history.
- Refreshes that leave the notes unchanged retain their deletion history. A changed structural
  baseline derives a new scope from the previous scope, so returning to an earlier visible
  pattern does not reuse retired identities. Host snapshots include empty-pattern scopes too;
  joining from another project must not prevent sharing the first note in a blank pattern.
- CRDT applies to notes. Project replacement, channel/pattern structure and plugin state retain
  their existing restrictions. Structural edits establish a fresh baseline; incompatible in-flight
  note history stops sharing and requires a resync. This is not an offline editing system.

Verification: 67 desktop checks, 60 local relay checks, 36 UI checks, 25 native synthetic harnesses,
the local HTTP transfer fixture, and a dedicated native-window geometry check. CRDT tests include
200 rounds with three replicas, reordered/repeated changes, concurrent moves/deletes, wire
validation, random-ID/allocation failure, history limits, pending MIDI edits, and a 6,000-note
incremental update. These are local/synthetic checks, not a new live FL24/25/26 session result.

**Deployment status:** the Worker changes are local and have not been deployed. The current
Cloudflare relay continues using locked snapshots. This package negotiates that fallback rather
than sending CRDT data to an older relay. No GitHub changes were sent. Native end-to-end MIDI
recording and FL24 compatibility remain unverified for this payload; previous successful runs
cannot certify it. See the versioned compatibility evidence for exact files and limits.

## Version 0.2.7: simpler version selection and checks before opening FL (2026-10-27)

- The dropdown has one entry for FL Studio 26, FL Studio 25 and FL Studio 24 when those releases
  are installed. Patch numbers and duplicate folders no longer fill the menu. Expand
  **Installation details** to see exactly which copy you are using.
- **Choose folder** still selects and remembers a particular installation, including another
  drive. A selected unsupported copy stays visible with its reason. Otherwise the menu prefers
  a reviewed copy, then an experimental copy, and uses numeric build order to choose between
  copies. Exact engine checks remain in place; short names do not imply universal patch support.
- Joining now checks the current host's build before starting FL. If your FL is older, the app
  explains that the person using the oldest build must create the room. A failed check can be
  retried and never opens an extra FL window. Missing hosts, invalid status and network failures
  also stop startup; the native handshake remains the final authority.
- Local relay tests cover all nine host/member pairings for the installed FL24/25/26 builds.
  Allowed pairs forward note, clip, metadata and parameter message markers in both directions
  with the right sender build and increasing sequence numbers. The three older-member/newer-host
  pairings are rejected before receiving a newer project. These synthetic checks do not prove
  that FL itself can open a project or apply recorded MIDI.
- Keyboard focus, long folder names, 320px windows and the real desktop at 200% zoom are checked.
  FL24 remains explicitly experimental. No native mappings were promoted, and no GitHub write
  or Cloudflare deployment is included in this update.

## Installed FL24 verification tools (2026-10-27)

The package checks now use installed FL **24.2.2.4597** and accept multiple copies of the same
version. Previously, the test still pointed to an extracted copy and failed when the newly
installed copy also appeared. Both packaged and portable checks now select FL24 in the real app
and verify its experimental notice. The app itself needed no rebuild. Local checks and current
relay probes pass; automatic approval review blocked the native collaboration launch. Project
sharing and MIDI remain unverified. [The evidence](client/dev/compatibility/fl24-installed-2026-10-27.json)
keeps this limitation separate from the passing installation checks. No GitHub write or relay
deployment occurred.

## Deployed relay hotfix: FL24 admission and clearer errors (2026-10-25)

The Cloudflare relay now accepts the exact **24.2.2.4597** compatibility declaration used by
the 0.2.6 experimental client. Previously, the deployed relay could reject that client with
**"Install the Cloudflare-enabled flim client on every participant's computer."** even though
the portable app already included its native client. The hotfix also gives separate explanations
for transport and compatibility failures, so a rejected build is not mistaken for missing files.

Worker version **`c5647634-648d-450d-ad79-a61c60b8336b`** contains only those admission and error-message
changes. The broader relay recovery, pending-room cancellation and queue/budget changes described
in the local updates below remain undeployed. This hotfix required no desktop rebuild and made
no GitHub push or release.

Production checks passed **9/9 non-admitting probes** and **24/24 checks in one disposable room**.
Synthetic clients declared an FL24 host and FL25/26 members; checks covered admission, note-message
marker forwarding in both directions between the host and each member, message ordering, room
status and cleanup. They launched no FL processes and made no R2 uploads or downloads. These
results verify relay behavior, not FL's handling of notes or projects. Native FL24 project sharing,
recorded MIDI and mixed-version editing remain unverified, and earlier failed native tests remain
unresolved. See [the deployed hotfix evidence](client/dev/compatibility/relay-fl24-hotfix-2026-10-25.json).

## Version 0.2.6: explicit FL24 testing and local diagnostics

This local update makes the existing FL **24.2.2.4597** candidate available for an intentional
test and makes failures easier to investigate. It does not establish verified FL24 sharing or
universal FL24–26 support. No GitHub push or Cloudflare deployment was made at this packaging
checkpoint; the later, narrow relay hotfix is recorded above.

- **FL24 has a clearly labeled test option.** Selecting the exact installation in the room app
  passes `--allow-experimental` to the native launcher. The launcher still checks the engine's
  fingerprint; it cannot borrow the mapping for an unknown patch build. The app prefers a
  non-experimental installation when one is available and there is no saved selection.
- **The test instructions state the remaining limits.** Use a disposable project copy, make
  FL24 the host when testing with newer versions, and use a licensed, unlocked installation
  so FL can reopen shared projects. The previous isolated FL24 project/edit checks failed.
  Enabling the test option does not resolve or replace those results.
- **Open test logs collects the relevant files in one place.** Each app run has a local folder
  containing desktop events and native FL logs. Logs record build and failure information;
  credentials and room codes are excluded from desktop events. Nothing is uploaded automatically.
  Native logs can include local paths and project/sample names, so review files before sharing them.
- **Diagnostics have size and workload limits.** Desktop logs rotate at 2 MiB, keeping three
  files; native logs rotate around 4 MiB, keeping three files per FL process. The desktop queue
  is bounded and drops diagnostic entries under overload. Disk failures disable diagnostics
  without preventing ordinary room actions. Older run folders are eligible for cleanup after
  seven days, but active or unrecognized folders are preserved, so the ten-run retention target
  is not a hard storage ceiling.
- **Crash reporting has a defined limit.** These files are best-effort logs, not crash dumps.
  Sudden process termination, disk failures or a full queue can leave out the final entries.

See [experimental FL24 testing and logs](client/desktop/README.md), [exact-build status](BUILD-COMPATIBILITY.md)
and [the current verification record](client/desktop/QA.md). Historical results below remain
tied to their original versions; this update does not claim a new successful live FL session.

## Version 0.2.5: protect projects and recover cleanly

This local update concentrates on failures that could lose edits, load the wrong sample, or
leave a session appearing healthy after FL rejected a change. It adds no new supported FL
builds. No GitHub push or Cloudflare deployment was made.

- **A failed save keeps the previous project.** Received projects are written to a temporary
  file beside the destination, checked and flushed, then moved into place. A disk-full error,
  locked destination or failed replacement leaves the previous destination intact. Creating
  a backup no longer moves the original out of the way. A failed backup preserves the old backup.
- **Joining cannot continue with a partial file.** File reads must finish completely. Failed
  snapshots, working-copy creation, sample rewriting and save-location changes stop sharing
  with an explanation. Project and preset files have a 64 MiB read limit. Very long paths fail
  cleanly, redirected Windows Documents folders work, and ANSI paths convert correctly to Unicode.
- **Quick edits stay in the right order.** Combining repeated preset updates no longer moves an
  update across a channel deletion, reorder or effect removal. A newly added channel receives
  its initial preset before the following edit can move or delete it.
- **Incomplete messages cannot turn into destructive edits.** Playlist clips, complete plugin
  snapshots, marker lists, mixer routes and pattern operations are checked before changes start.
  Missing channels, duplicate targets, invalid numbers and damaged encoded data are rejected.
  Complete plugin snapshots reserve enough queue space for the whole change before adding any task.
- **Rejected plugin edits remain failures.** If FL rejects a preset or cannot remove an effect,
  flim keeps the last agreed state and stops sharing. It no longer records the failed operation
  as successfully synchronized. A native failure may already have changed some FL state, so
  users must check the local project before reconnecting; this is not an undo mechanism.
- **Sample rewrites preserve the original bytes on failure.** Nested plugin records and trailing
  file data survive rewriting. Failed allocations cannot replace a complete file with a partial
  rewrite. Reusing a local sample alias now checks file identity or contents, not only file size.
  If a known sample cannot be mapped safely, sharing stops before FL loads the wrong file.
- **Reconnecting forgets the previous room's sample choices.** Path mappings, declined uploads
  and the private file key are cleared on disconnect. Old workers cannot restore those choices.
  The declined list is deduplicated and capped at 4,096 entries. Optional file-hash caching stays available.
- **Preparing a full plugin snapshot handles low memory.** Failed allocation or an incomplete
  channel snapshot cannot send a partial replacement to the other participant. The combined
  plugin message is capped at 64 MiB; sample rewriting is capped at 128 MiB.
- **The room app keeps working when settings cannot be saved.** It preserves the previous
  preferences and explains that the name or FL folder may need selecting next time. Canceling
  the folder picker keeps the selected FL version. Eight-digit room codes accept spaces and
  hyphens; closed rooms disable refresh. Clock corrections no longer stall participant polling,
  and oversized response downloads are canceled promptly.
- **A stalled connection cannot hold unlimited relay work.** Request-body reads time out after
  ten seconds. Each connection can queue up to 2,000 frames or 2 MiB, with shared limits of
  8,000 frames or 8 MiB. Oversized messages are checked before queuing. Edits waiting behind a
  disconnected sender are discarded and its locks released.
- **Abandoned R2 files cannot hide behind active uploads.** Cleanup skips uploads still in
  progress before choosing its next 64-file deletion batch. Storage reservations remain charged
  until deletion succeeds. Existing storage/monthly cutoffs are retained; these new relay fixes
  require a later authorized deployment.

Verification and remaining live-FL limitations are recorded in [QA.md](client/desktop/QA.md)
and [the 0.2.5 evidence record](client/dev/compatibility/sweep-2026-10-25-pass2.json).

## Version 0.2.4: broader reliability and interface sweep

This local update fixes more failure paths and improves the room app. It does **not** establish
universal FL 24–26 compatibility. The fresh FL25/26 collaboration attempt passed **0 of 6**
basic checks while the disposable applications displayed license/update prompts and the member
reported trial mode. Earlier successful runs remain historical evidence for their original files.

- **Slow connections cannot grow the edit backlog forever.** Upload/download waiting lists and
  edits held during project loading now have count and memory limits. Reaching a limit stops
  sharing with an explanation so edits are not silently dropped while the session appears healthy.
- **Sample bookkeeping uses bounded memory.** The optional file-hash cache retains at most 8,192
  entries. A failed cache allocation simply skips caching. Replacing a sample path preserves the
  working path if the replacement cannot be allocated.
- **Damaged note and channel messages cannot become partial edits.** Whole-pattern snapshots are
  validated before changes are queued. Incomplete note records, repeated pattern IDs, missing
  fields and incomplete channel reorder lists stop sharing. An intentionally empty pattern still works.
- **Low memory and disk errors have clearer outcomes.** Failed allocations for queued edits,
  outgoing notes/projects and received plugin states stop sharing. A plugin file must be written
  completely before FL can load it. Failed plugin-state restoration cannot queue a partial file.
- **Returning after a failed launch can release the unused room.** A new authenticated relay
  operation releases only the matching pending host reservation. It cannot close an active room.
  If the relay is offline or does not yet have this operation, the app returns to the form and
  explains that the reservation will expire. This relay change is tested locally and undeployed.
- **Finding FL installations does less repeated work.** Directory aliases are checked once,
  up to three installation checks run together, and a broken installation does not stop discovery.
  Selection and display order stay consistent.
- **Room controls are easier to use.** Typed spaces/hyphens and the caret stay intact when editing
  a room number. Buttons have larger targets, input outlines and placeholders have stronger
  contrast, and small windows can scroll to every control. Old copy-feedback timers and delayed
  status requests cannot affect the next room visit.
- **The app explains the FL24 testing status before launch.** The unverified 24.2.2.4597 mapping
  is unavailable in the desktop picker until a reviewed profile exists. Developer investigation
  remains possible. Unknown patch builds continue to require their own reviewed mapping.

Local checks passed: **21 native test programs, 4 native HTTP transfer checks, 72 Python tests,
35 Cloudflare emulator tests, 56 legacy relay tests plus 58 session checks, 32 desktop bridge
tests and 26 UI checks**. See [the feature matrix and packaging results](client/desktop/QA.md)
and [the exact-build policy](BUILD-COMPATIBILITY.md). No GitHub push or Cloudflare deployment
was made in this sweep.

## FL 24 compatibility work and project-loading fixes

FL **24.2.2.4597** now has an experimental mapping and adapters for its older mixer and
playlist formats. This is still a candidate, not verified FL 24 support. The official signed
build started and joined a local test room, but it reported trial mode and refused to reopen
the shared project. Both six-check edit runs failed. Mixed sessions with FL 25/26 and recorded
notes in FL 24 remain unverified. No reviewed FL 24 profile or updated desktop package is released.

- FL 24 reports a missing control differently from FL 25/26. flim now recognizes that value
  for this exact build. The isolated runtime watched 508 controls after the fix instead of
  exhausting its 65,536-control limit with nonexistent entries.
- Incoming mixer edits cannot target tracks or effect slots outside the local build's limits.
  This also prevents a newer participant's extra mixer tracks from reaching FL 24's smaller mixer.
- FL 24's 60-byte playlist clips convert to the existing shared format. If a newer clip contains
  fields FL 24 cannot represent, flim refuses the change before replacing the local clips.
- When FL refuses or faults while loading a shared project, flim stops sharing, reports the
  failure and does not assign the received filename as the save target. It no longer reports
  a failed load as opened or continues applying queued edits to an unrelated project. FL's busy-state cleanup also runs
  after a loader fault. This failure handling applies to FL 25/26 too.
- If FL has not finished starting within the readiness timeout, flim leaves sharing disabled.

Exact build checks remain in place. Unknown FL 24 builds are refused. The normal client remains
FL 25 only; the existing experimental build flag also includes the FL 24 candidate. See
[the investigation](client/dev/compatibility/24.2.2.4597-investigation.json) and
[validation status](client/dev/compatibility/24.2.2.4597-runtime.json). These changes stay local;
there was no GitHub push or Cloudflare deployment.

## Latest update: a small Windows room app

Version **0.2.3** fixes several problems found in a deeper reliability review:

- **The people list recovers on its own.** A temporary connection error previously stopped automatic updates. It now retries, keeps the last verified list, and shows when a refresh is running. Repeated clicks cannot hide an error before a successful check. Leaving a room cancels its lookup so it cannot interfere with another room.
- **Less background network traffic.** Active rooms check the people list every thirty seconds. Hidden or offline windows pause those checks and refresh when available again. Waiting rooms check every five seconds so connecting people appear sooner. This changes the app's people list, not the speed of musical edits inside FL Studio.
- **Large sample lists can be shared.** Projects with more than 512 sample references previously exceeded the relay's lookup limit and could skip sharing their samples. The client now splits the list into accepted batches; a native network check covered 1,025 references.
- **Transfers handle interruptions correctly.** Uploads finish every part of a partial network write. Downloads stop writing when their session changes and cannot exceed the relay's file-size limit. Cloudflare samples above 90,000,000 bytes are skipped before expensive hashing or upload.
- **Relay recovery fixes are ready locally.** Failed file cleanup schedules another attempt while retaining its storage reservation. Startup restores missing cleanup/reservation alarms. A file missing from R2 can be uploaded again after a failed download clears its stale tracking entry. The persistent shared budget remains in place. These server changes have not been deployed.

The updated portable app was built and opened successfully. Automated bridge, UI, local relay and native transfer checks passed; [the verification record](client/desktop/QA.md) separates those checks from earlier live FL collaboration tests. Supported build gates remain exact. This update does not make untested FL versions compatible.

Version **0.2.2** adds a matching logo based on the two connected computers and MIDI keyboard.
It appears beside the app name, on the Windows executable, in the window title bar and on the
taskbar. The icon contains nine sizes so Windows can choose one suited to the display.

Version **0.2.1** replaces the portrait behind Get started with an illustration of two music
computers connected to a MIDI keyboard. The artwork is included in the app and stays clear in the
compact card. The portrait is removed from the bundled public assets.

You can now press **Get started**, enter a name, and create or join a room with an eight-digit
number. The app finds installed FL versions, checks that flim supports the chosen build, and opens
a new FL Studio window for the room. There is no signup. Copy the invitation number to share it
with a friend, and the app shows the people who have actually connected.

The interface uses the supplied Framer card and General Sans fonts. Its expanding area now
contains room controls instead of portfolio information. Everything needed to draw the app is
bundled locally, so opening it does not fetch fonts or images from outside websites.

The Cloudflare relay now keeps up to four rooms separate, with eight people in each. Edits, files,
project locks and cleanup belong to their own room. The existing R2 budget remains shared across
all rooms and survives updates. An unused reservation expires after ten minutes; a running session
does not have that countdown. The original `/01` connection still works.

Friends can create rooms without your private hosting key. Each reservation gets its own one-use
hosting ticket, which stays outside the interface and is not saved in preferences. Repeated room
number guesses, room creation and status checks are limited to protect the free-tier service.

The app prevents duplicate launches, refuses unverified FL builds, ignores old status replies after
you leave a room, and explains startup/network failures. **Return to start** leaves launched
FL Studio windows open. In version 0.2.4 it also attempts to release an unused host reservation
after a failed launch. The host closing FL Studio ends that actual session.

See [the app instructions and verification](client/desktop/README.md). This is a local Windows
build, with the room service deployed to the existing Cloudflare Worker. Nothing in this update
has been pushed or released on GitHub.

## R2 protection and ongoing piano-roll edits

The Cloudflare relay now keeps a persistent usage budget. It refuses new files before stored data
would exceed **512 MiB or 2,000 files**, refuses uploads after **20,000 attempts per UTC month**, and
refuses downloads after **100,000 attempts per UTC month**. Restarting a session or deploying an
update does not clear those counters. Failed transfer attempts count too. Cleanup continues at
the limit, so temporary files can still be removed. These are limits for this relay, not a spending
cap on everything in your Cloudflare account. See [the cutoff and usage command](server/cloudflare/README.md#automatic-r2-cutoff).

An upload could previously finish while cleanup was removing its tracking record, leaving a file
that the relay no longer counted. Active uploads now retain their reservation; cancelled or
failed writes finish before cleanup removes them. File streams must match their reserved size.
Metadata-only checks no longer consume the download allowance.

Previously, note sharing waited for a pause in editing. Continuous recording could keep moving
that pause farther away, so the other person saw no notes until recording stopped. The client now
schedules a note update during continuous editing at roughly half-second intervals, plus a final
update after editing settles. This applies to both hosts and members. Local changes made just
after a remote update are retried rather than forgotten. A slow FL main thread keeps one pending
snapshot per pattern instead of accumulating duplicate work. Network and FL load still affect
when a remote update appears; this is not an audio-latency guarantee.

Large selected patterns also take less work to update: selection matching now uses sorting and
lookup instead of comparing every incoming note against every old note. A failed note read no
longer looks like an intentionally emptied pattern. Relay rejection and R2 cutoff errors now stop
sharing with an explanation while leaving local edits in FL.

Setup now recognizes reviewed external build profiles and reports damaged profiles before launch.
Folder edits wait briefly before checking compatibility, and duplicate Windows installation paths
are scanned once. Profile export rejects ambiguous review files and will not overwrite another
review created at the same time. This improves adding reviewed FL25/26 builds; it does not make
unknown builds safe automatically.

For the broadest editing freedom, use the same supported FL build. Both people can then add and
edit channels and notes. In mixed-build sessions, supported note and control edits still travel
both ways, while newer plugin presets and channel creation remain restricted to the host's exact
build. Only the host can replace the shared project. Unrecorded live MIDI audition and audio
streaming are separate features and are not added by this update.

The latest client passed 30 native FL recording/edit checks across local mixed-build, local FL26
and deployed mixed-build sessions. The relay passed 20 local regression tests and 14 live checks;
16 native harness executables and 60 Python tests also passed. Physical MIDI hardware was not
tested. Exact binaries, source and logs are identified in [the verification record](client/dev/compatibility/reliability-runtime.json).

## 1. FL Studio 26 support, with FL Studio 25 support retained

FL Studio updates can move the internal functions and data that flim uses. The old address list cannot safely be reused just because the program still looks similar.

The fork now uses a separate verified address list for each supported build. The launcher and the program loaded inside FL agree on which builds are supported. When a selected build is unsupported, the launcher offers to open ordinary FL without flim instead of guessing how to modify it.

| FL Studio build | What was checked |
|---|---|
| **26.1.7.5654** | The currently installed FL 26 build. Current binary checks are recorded below; historical 31-check results are preserved separately. |
| **25.2.5.5319** | The currently installed FL 25 build. Uses the same experimental client as FL 26, with its own verified profile. |
| 26.1.6.5639 | Its support table is retained. Earlier live results exist, but that installation was replaced by the update and was not rerun with the newest client. |
| 25.2.3.5171 and 25.1.6.4997 | Their support tables are retained and passed simulated hook-selection checks. These older builds were not rerun live after this update. |

The experimental Windows client supports the builds listed above. The normal build contains the three FL 25 tables. Building with `FLIM_EXPERIMENTAL_FL26=1` includes FL 26; see [client build instructions](client/README.md).

**Different supported builds can now collaborate when the oldest build hosts.** The current
FL 25 host and FL 26 member passed 34 mixed-session checks. Supported notes, knobs, naming,
colors, routing and playlist changes can travel in both directions. Whole presets, channel
creation must come from someone on the host's exact build. Project replacement remains host-only. A newer
member making an incompatible change stops sharing, while keeping their local change.

A small compatibility profile can add a reviewed FL 25/26 build without recompiling flim. The
launcher and injected engine both check the exact engine fingerprint and require every address
and layout field. A damaged or mismatched profile is refused. Unknown updates still need review
and testing. See [build support and mixed sessions](BUILD-COMPATIBILITY.md).

When the host opens an older project, flim uses that host's current project writer for the
shared snapshot. It preserves the actual version stamp and refuses newer projects at older loaders.

Delayed edits and unresolved parameter values are now discarded when their session ends, even
if they finish after a reconnect. Local renames also survive unrelated channel deletion/reordering
and remote metadata changes that arrive before the next scan.

## 2. Project files and presets are read more reliably

Some saved FL files use a longer form of an event identifier. The old reader misunderstood it, which could hide sample paths from flim's transfer system.

Both project readers now recognize that form, check that the file has enough data before reading it, and preserve event data they do not otherwise interpret. A corpus check successfully read **8,738 installed presets and projects**, including 128 extended events.

Incoming project data is also checked for a valid, consistent FL version before flim rewrites sample paths, writes a local project copy or asks FL to load it. Missing, malformed or conflicting version information is refused. This reduces the chance of loading a project that the receiving FL build cannot safely interpret.

## 3. Received plugin presets stop fighting with local monitoring

While FL loads a received plugin preset, it can briefly report default parameter values. Previously, flim could mistake those temporary values for your edits and send them back to your friend. That could make a newly loaded preset revert or change unexpectedly.

The client now tracks which loading operation an observation belongs to. Observations and queued changes from an older loading operation are discarded. This keeps temporary intermediate values from overwriting the received preset.

This was tested with controlled loading cases and live effect loading. It is not a promise that every third-party plugin has been tested.

## 4. Downloaded samples can be shared again after saving

FL sometimes saves sample locations using the `%ILSharedData%` shortcut instead of a full Windows path. Previously, flim could lose track of a downloaded file when that shortcut appeared in a later save.

The client now resolves the shortcut using FL's configured shared-data folder. A sample that was downloaded, saved and referenced through that shortcut can remain available for the normal transfer process.

Samples stored inside compressed or encrypted plugin data, including some Kontakt content, remain a limitation.

## 5. Switching projects clears the previous project's edit locks

Imagine someone reserves a control in Project A, then the host opens Project B. The new project may reuse the same internal control number. Previously, the old reservation could block an edit in Project B until it timed out. One older project-switching path cleared the server's reservations without telling the clients.

Both project-switching paths now notify clients that the old locks have been released before sending the replacement project. The host is notified too. The new project can immediately reuse those control numbers. Normal full-state updates preserve existing locks because they do not represent a different project.

Only an accepted project replacement from the host clears these locks. A member's rejected replacement request cannot clear another person's reservations.

## 6. Expired edit locks stop blocking people

A lock is supposed to expire after 30 seconds without a valid renewal. Previously, it could keep blocking edits until a later cleanup timer ran. Some traffic could revive an already expired lock, rejected edits could keep other locks alive, and new participants could receive stale reservations.

The server now checks expiry when a lock is used or sent to a new participant. Accepted edits renew active locks; cursor movements and rejected edits do not. Expired entries are also removed before applying the limit on how many active locks a session may hold.

The practical effect is fewer situations where a control stays marked as occupied after its reservation should have ended.

## 7. Only the host can replace the shared project or complete state

The clients treated certain whole-project and whole-state messages as host instructions, but the old server could forward those messages from any member. That could leave the host and members looking at different results.

The server now rejects these replacement messages from members. Members can still make ordinary supported edits and request the host's current state.

The server also rejects ambiguous control fields hidden inside another message. This matters because the existing client recognizes some instructions by searching the incoming text. The server checks prevent a nested or disguised field from being interpreted as a different instruction. Replacing the client's text-search parser with a complete parser remains separate work.

## 8. Sample transfers handle disappearing files and session expiry

Several failures happened between checking a file and actually using it:

| Before | Now | Why it matters |
|---|---|---|
| A new upload could be deleted by the cache cleanup that its own completion triggered. | That cleanup pass protects the file that just finished uploading. | A successful upload is not immediately undone by its own cleanup. Later uploads can still evict it. |
| A download could announce success before opening its file. If cleanup removed the file in that gap, the connection reset. | The server opens the file and checks its metadata before announcing success. A file already gone gets a complete "not found" response. | Clients receive a clear result instead of a broken transfer. |
| A download could lose its path after the file was opened. | The transfer reads through the already-open file handle. | Removing the cache path does not interrupt those opened bytes. |
| A session ending while a download's file lookup was pending could still receive the file. | The server rechecks the session before sending success headers or sample bytes. | Work waiting on disk does not continue as though the session were still active. Transfers already streaming are not revoked by this change. |
| A sample-list request could finish after its session ended. | Session validity is checked again after its request body arrives. | The server refuses the expired request before checking the old storage. |

Disconnected requests and failed file checks close their opened handles. Downloads and file-size requests now perform their initial file lookup asynchronously, allowing the server to handle other work while that lookup is pending.

## 9. Sample storage limits and cleanup are more dependable

Uploads are streamed to disk and checked against the promised content hash. A hash is a fingerprint of the file's bytes; this check detects an upload whose contents do not match the requested file.

An upload must fit both the individual-file limit and its session's cache limit. In-progress uploads reserve their declared size against the total storage budget, so several simultaneous uploads cannot each claim the same free space. Failed or disconnected uploads clean up their temporary files and release their reservations.

A regression also covers two people uploading the same sample: a late disconnect after a file is committed must not delete a valid copy used by the other upload.

Cleanup preserves the configured parent folder and unrelated files. Sample responses tell intermediaries not to cache this private session data. Keep one server process per cache directory, as described in the [server instructions](server/README.md).

The cache remains temporary storage. Keep your own project and sample originals.

## 10. Less repeated work, with clearer performance limits

- **Repeated sample references:** if a project lists the same sample fingerprint several times, the server checks that file once and lists a missing file once.
- **Plugin monitoring:** the client counts activity in one pass instead of repeatedly recounting changes for each plugin. This reduces work in that specific monitoring loop.
- **Sending to several friends:** the server prepares an outgoing message once and reuses it for the recipients, instead of recreating the same text for each person.
- **Slow connections:** a peer's queued outgoing data is limited, so a connection that stops reading cannot grow its server queue indefinitely.
- **Download lookup:** initial file opening and metadata checks no longer use a synchronous path-stat call on the server's main event loop.

Local measurements showed improvements in the monitoring loop and message-preparation work. Those are measurements of individual pieces, not evidence of a particular increase in FL's frame rate, lower audio latency, or faster internet transfers. Upload storage accounting and cache eviction still scan files synchronously and remain an area for further work.

## 11. Startup, connection handling and developer tests are safer

The launcher checks whether loading flim into its newly started FL process succeeded. Unsupported builds and failures are handled more deliberately, including long installation paths. Incoming network messages have bounded buffer growth, and connection cleanup was tightened.

Invalid server settings, such as an impossible file-size limit or a nonnumeric timeout, now stop startup before cache cleanup or listening begins. Proxy headers are trusted only in the configured proxy mode; Cloudflare Tunnel mode expects a local origin connection.

Developer tools require explicit reference files or test-process selections, reject ambiguous address matches, and report failed checks with a failing exit status. The restart tooling checks a saved process's number, creation time and executable before stopping it, so an unrelated FL session is preserved.

Server dependencies were updated. The container configuration uses Node.js 24 and a non-root user. The Docker image itself was not built in this testing pass.

## 12. No separate Syncthing integration

The optional Syncthing file companion was removed from the current source and packages. flim's existing project and sample transfer remains the supported path in this fork. No personal Syncthing installation, device pairing, shared folder or configuration was changed.

## What testing actually established

| Checkpoint | Results | What this does and does not mean |
|---|---|---|
| Current profiles and negotiation | **34/34 feature checks passed in each of three pairs:** FL 25 hosting FL 26, FL 25 with FL 25, and FL 26 with FL 26. | Same final experimental client binaries and updated relay. Mixed checks include member edits back to the host. |
| Current compatibility refusals | **Both native checks passed.** | A newer member's whole preset stopped sharing and left the older host unchanged. An older member was refused before receiving a newer host's project. |
| Current offline checks | **57 Python tests, 56 Node tests, 58 session checks, 14 native harnesses and 20 ownership checks passed.** | Includes complete profile validation, an uncompiled synthetic build profile, malformed negotiation, stale-session work, stale undo cleanup and local rename regressions. |
| Historical server transfer changes, commit `a4ae092` | **44 Node tests and 58 session checks passed.** | Includes local HTTP and WebSocket tests for transfer races, cache limits, lock handling, session separation and existing behavior. |
| Historical transfer checkpoint with the installed FL builds | **2 focused live checks passed per build**, on 26.1.7.5654 and 25.2.5.5319. | A receiver with local lookup disabled downloaded a fresh synthetic sample, and the saved channel state referenced matching cached bytes. This was not a new full feature run. |
| Previous server revision, commit `a8513d4` | **31 live feature checks passed on each current build; 36 Node tests, 58 session checks and 48 Python tests passed.** | Full feature coverage included project joins, parameters, mixer settings, channels, notes, markers, effects, reordering, clips and samples. |
| Earlier client compatibility work | Both normal and experimental clients built; parser, launcher, buffer, preset-race and supported-build checks passed. | Detailed records identify the binaries and scope of each historical run. |

Three selected transfer scenarios failed before the historical transfer fixes and passed afterward. Tests deliberately control timing and file callbacks to reproduce rare races. This gives repeatable evidence; it does not mean every possible bug is fixed.

Live checks used disposable same-build and mixed-build FL pairs with loopback servers. All owned test processes were stopped by their saved identities. Installed FL files were not patched. Long sessions, broad third-party plugin coverage, remote-network performance, audio-render comparisons and Linux runtime behavior remain untested in the latest pass.

See the [current runtime record](client/dev/compatibility/mixed-profile-runtime.json), [compatibility evidence](client/dev/compatibility/README.md), [original source audit](server/AUDIT.txt), [project-lock audit](server/CONTINUED-AUDIT.txt) and [sample-transfer audit](server/TRANSFER-AUDIT.txt) for evidence and limitations. The JSON audit files preserve the state at their own checkpoints; their `pushed: false` entries describe when the tests were recorded, before GitHub publication.

## What you need to update

1. **For FL 26 support and client fixes:** build the experimental Windows client and keep `flim.exe` and `flim_engine.dll` together. Keep the `profiles` folder beside them. Update everyone's client and relay; the oldest supported build hosts, and all participants need the required plugins.
2. **For the relay and sample-transfer fixes:** run the revised server from this branch. Updating only the client does not update an older server.
3. **For friend testing:** start with project copies and a server you control. [Private testing instructions](server/DEPLOYMENT.md) explain the server and Cloudflare Tunnel setup.

The supplied server targets **Fly.io**. This fork does not contain a Cloudflare Workers backend. Cloudflare Tunnel can provide the public connection to a separately running Node.js server, but account setup and deployment are still separate steps. Publishing this code on GitHub does not deploy it, update the upstream public relay or create a new downloadable release.
