// flim engine (native, injected into FL). v3: params + plugin state + channels.
//  - joins a named room on flim-server (first in = leader)
//  - DETECT: polls params through FL's ProcessRECEvent (f4e910, REC_GetValue)
//            and sends param.set ops keyed by REC event id. Watched: channel
//            vol/pan/on-off/route, channel plugin params, mixer vol/pan/stereo/mute,
//            mixer effect params; rescanned every few seconds for new channels/plugins
//  - PLUGINS: each channel / mixer FX slot is a "unit"; its full state (FL .fst via
//            FL's own preset saver) is sent on plugin add/replace, preset-sized param
//            bursts, or hash changes found by a slow sweep (e.g. Serum wavetables), and
//            applied with FL's preset loader. Channel add/delete are replayed too.
//  - JOIN: a member sends state.req; the leader answers with plug.full + state.full
//  - APPLY: inbound param.set is queued and executed on FL's main thread
//           (WH_GETMESSAGE hook) via ProcessRECEvent(REC_UpdateValue|REC_UpdateControl)
//  - LOCKS: a param is locked while we tweak it, released after a short idle;
//           params locked by a peer are snapped back if tweaked locally
//  - PATTERNS: insert / clone / delete / split are hooked (TFLProject vmt) and replayed as calls
//  - FOCUS: which FL window each person last used, shown next to the status
//  - NET: WinHTTP WebSocket (ws:// or wss://). The desktop app supplies the room connection;
//         FL's toolbar shows status and unavailable-sound hints.
// Config: user name from flim.ini (set by flim.exe). Env overrides for dev/tests:
//         FLIM_NAME, FLIM_AUTOCONNECT=<session link> (+ FLIM_PASSWORD) joins at startup;
//         with FLIM_HOST=1 it is a server address to host on instead (+ FLIM_OWNER_KEY = slot 00);
//         legacy FLIM_SERVER=host:port means FLIM_AUTOCONNECT=ws://host:port.
//         Tests only: FLIM_SAMPLE_NOLOCAL=1 (always download samples), FLIM_CURSOR_NOCOVER=1 (show
//         other people's arrows even where another window covers FL).
// Logs to FLIM_LOG_DIR\native-<PID>.log when set; otherwise %TEMP%\flim_engine.log.

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <ctype.h>
#include <shlobj.h>
#include "../common/flim_config.h"
#include "../common/flim_res.h"
#include "../common/flim_version.h"
#include "../common/flim_ws_buffer.h"
#include "../common/flim_unit_bursts.h"
#include "../common/flim_clip.h"
#include "../common/flim_plugin.h"
#include "../common/flim_files.h"
#include <bcrypt.h>
#include <commctrl.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "version.lib")

#define FL_MODULE    L"FLEngine_x64.dll"
#define IMG_BASE     0x400000      // Ghidra image base; runtime addr = module + (VA - IMG_BASE)

// ---------------- FL builds ----------------
// Everything flim uses inside FLEngine_x64.dll: function / global addresses (Ghidra VAs, image base
// IMG_BASE) and the object offsets that differ between builds. One row per supported FL build; the
// engine picks the row whose version matches the loaded FLEngine_x64.dll (no row = flim stays off).
// 25.2.3.5171 is the reference, found by hand. Other rows are mapped from it with dev/sigscan.py
// (function signatures, call sites, function order, globals by their references, offset drift) and
// then tested in FL.
#include "../common/flim_profile.h"
#include "../common/flim_json.h"
#include "../common/flim_cloud.h"
#include "../common/flim_notes_crdt.h"

static const FlBuild k_flBuilds[] = {
    {   // FL Studio 2025 (25.2.3.5171): the reference
        .build = L"25.2.3.5171", .msgbox = 1,
        .REC           = 0xf4e910,
        .MUTE          = 0x1176be0,
        .MIXARR        = 0x1496718,
        .MIXCNT        = 0x14980b8,
        .MAINFORM      = 0x1497368,
        .SAVEPRESET    = 0xe71f20,
        .LOADPRESET    = 0xe72110,
        .HASPLUGIN     = 0x12204f0,
        .GETPLUGIN     = 0x1222030,
        .INTFCLEAR     = 0x41a770,
        .ADDCHAN       = 0xf1ceb0,
        .DELCHAN       = 0xf1d6c0,
        .RESOLVER      = 0xf1e370,
        .CHANLIST      = 0x1498140,
        .MOVECHAN      = 0xf4a780,
        .MOVEOBJ       = 0x1497460,
        .MOVEARG       = 0x1499868,
        .CHANFILT      = 0x14961d0,
        .PATARR        = 0x1498920,
        .NOTEARR       = 0x11cb490,
        .NOTEDEL       = 0xf665d0,
        .NOTELOCK      = 0x1497f30,
        .GRIDREFRESH   = 0x11d04f0,
        .FLPROJ        = 0x149a508,
        .MAINOBJ       = 0x1496fb8,
        .SETPROJ       = 0x10cb1e0,
        .SAVEPROJ      = 0x10cdf80,
        .BUSYBEGIN     = 0x10c1e70,
        .BUSYEND       = 0x10c1ec0,
        .PROJNAME      = 0x156f2a0,
        .ARRS          = 0x18209d8,
        .ARRCUR        = 0x148d1dc,
        .PLFORM        = 0x14993e8,
        .PLREFRESH     = 0xd40250,
        .HINT          = 0x10e49f0,
        .MIXNAME       = 0x11b9ce0,
        .MIXCOLOR      = 0x11bcd60,
        .UIUPDATE      = 0xb69db0,
        .MIXOBJ        = 0x1498208,
        .SETROUTE      = 0x119e180,
        .ROUTEUPD      = 0x119d6d0,
        .PATNAME       = 0x11cad70,
        .PATCOLOR      = 0x11cb260,
        .PATREFRESH    = 0xd9a9e0,
        .PLTRACK       = 0x11dec90,
        .MARKADD       = 0xf69960,
        .MARKTYPE      = 0xf5bf38,
        .DYNSETLEN     = 0x417fc0,
        .MARKREFRESH   = 0xd4bc60,
        .MARKSORT      = 0xf692d0,
        .PATLENUPD     = 0x11cb550,
        .PATMARKS      = 0x11ca910,
        .SONGLOCK      = 0x1499b38,
        .MODIFIED      = 0x10c7570,
        .TSNUM         = 0x14997d0,
        .TSDEN         = 0x1497bd0,
        .TSSET         = 0x1255160,
        .TSCTLS        = 0x12552d0,
        .MSGBOX        = 0xa885e0,
        .MSGBOX_CORE   = 0xa88560,
        .PRFORM        = 0x1498380,
        .CURPAT        = 0x1499de0,
        .CH_SELECTED   = 0x35c,
        .CH_GRID       = 0x7bc,
        .FORM_BUSY     = 0x3344,
        .PAT_STRIDE    = 0xc0,
        .PLFORM_PATS   = 0xd00,
        .PL_MARKSEL    = 0xd58,
        .ED_TICKSPERPX = 0xaec,
        .ED_HSCROLL    = 0xafc,
        .PR_GRID       = 0xc40,
        .PL_GRID       = 0xcf8,
        .GRID_VSCROLL  = 0x3fc,
        .MIX_STRIDE    = 0x1474,
        .MIX_SLOTS_OFF = 0x1324,
        .MIX_ROUTE     = 0x2e4,
        .FLPROJ_LOAD_SLOT = 0x38,
        .PATOP_CLONE_SLOT = 0xd8,
        .PATOP_DELETE_SLOT = 0xe0,
        .PATOP_REARRANGE_SLOT = 0xe8,
        .PATOP_EDIT_SLOT = 0xf0,
        .PATOP_INSERT_SLOT = 0xf8,
        .PATOP_SPLIT_SLOT = 0x100,
    },
    {   // FL Studio 2025 (25.1.6.4997): dev/sigscan.py from 5171, checked by hand where noted
        .build = L"25.1.6.4997", .msgbox = 2,
        .REC           = 0xf53b50,
        .MUTE          = 0x117e3c0,
        .MIXARR        = 0x149b8c0,
        .MIXCNT        = 0x149d258,
        .MAINFORM      = 0x149c510,
        .SAVEPRESET    = 0xe723a0,
        .LOADPRESET    = 0xe72590,
        .HASPLUGIN     = 0x122aef0,
        .GETPLUGIN     = 0x122ca30,
        .INTFCLEAR     = 0x41a770,
        .ADDCHAN       = 0xf1fd70,
        .DELCHAN       = 0xf20580,
        .RESOLVER      = 0xf21270,
        .CHANLIST      = 0x149d2e0,
        .MOVECHAN      = 0xf4fa00,
        .MOVEOBJ       = 0x149c610,
        .MOVEARG       = 0x149e9f0,
        .CHANFILT      = 0x149b368,
        .PATARR        = 0x149dab8,
        .NOTEARR       = 0x11d66a0,
        .NOTEDEL       = 0xf690d0,
        .NOTELOCK      = 0x149d0d0,
        .GRIDREFRESH   = 0x11db2a0,
        .FLPROJ        = 0x149f690,
        .MAINOBJ       = 0x149c158,
        .SETPROJ       = 0x10c88f0,
        .SAVEPROJ      = 0x10d00e0,
        .BUSYBEGIN     = 0x10bf5f0,
        .BUSYEND       = 0x10bf640,
        .PROJNAME      = 0x1574240,
        .ARRS          = 0x181ec10,
        .ARRCUR        = 0x14924e4,
        .PLFORM        = 0x149e580,
        .PLREFRESH     = 0xddca90,
        .HINT          = 0x10ec200,
        .MIXNAME       = 0x11c5090,
        .MIXCOLOR      = 0x11c80d0,
        .UIUPDATE      = 0xbe9880,
        .MIXOBJ        = 0x149d3a8,
        .SETROUTE      = 0x11aa090,
        .ROUTEUPD      = 0x11a95e0,
        .PATNAME       = 0x11d5fa0,
        .PATCOLOR      = 0x11d6490,
        .PATREFRESH    = 0xe3bd20,
        .PLTRACK       = 0x11e98e0,
        .MARKADD       = 0xf6c3e0,
        .MARKTYPE      = 0xf610c8,
        .DYNSETLEN     = 0x417fc0,
        .MARKREFRESH   = 0xde84b0,
        .MARKSORT      = 0xf6bd50,
        .PATLENUPD     = 0x11d6750,
        .PATMARKS      = 0x11d5b50,
        .SONGLOCK      = 0x149ecd0,
        .MODIFIED      = 0x10c4c80,
        .TSNUM         = 0x149e960,
        .TSDEN         = 0x149cd70,
        .TSSET         = 0x1260b70,
        .TSCTLS        = 0x1260ce0,
        .MSGBOX        = 0xa88000,
        .MSGBOX_CORE   = 0x0,
        .PRFORM        = 0x149d520,
        .CURPAT        = 0x149ef68,
        .CH_SELECTED   = 0x344,
        .CH_GRID       = 0x78c,
        .FORM_BUSY     = 0x3004,
        .PAT_STRIDE    = 0xa4,
        .PLFORM_PATS   = 0xcf8,
        .PL_MARKSEL    = 0xd50,
        .ED_TICKSPERPX = 0xae4,
        .ED_HSCROLL    = 0xaf4,
        .PR_GRID       = 0xc38,
        .PL_GRID       = 0xcf0,
        .GRID_VSCROLL  = 0x400,
        .MIX_STRIDE    = 0x1474,
        .MIX_SLOTS_OFF = 0x1324,
        .MIX_ROUTE     = 0x2e4,
        .FLPROJ_LOAD_SLOT = 0x38,
        .PATOP_CLONE_SLOT = 0xd8,
        .PATOP_DELETE_SLOT = 0xe0,
        .PATOP_REARRANGE_SLOT = 0xe8,
        .PATOP_EDIT_SLOT = 0xf0,
        .PATOP_INSERT_SLOT = 0xf8,
        .PATOP_SPLIT_SLOT = 0x100,
    },
    {   // FL Studio 25.2.5.5319: see dev/compatibility/
        .build = L"25.2.5.5319", .msgbox = 1,
        .REC                   = 0xf53fe0,
        .MUTE                  = 0x117f050,
        .MIXARR                = 0x14a7eb0,
        .MIXCNT                = 0x14a9850,
        .MAINFORM              = 0x14a8b00,
        .SAVEPRESET            = 0xe78dc0,
        .LOADPRESET            = 0xe78fb0,
        .HASPLUGIN             = 0x12297e0,
        .GETPLUGIN             = 0x122b320,
        .INTFCLEAR             = 0x41a770,
        .ADDCHAN               = 0xf215e0,
        .DELCHAN               = 0xf21df0,
        .RESOLVER              = 0xf22ac0,
        .CHANLIST              = 0x14a98d8,
        .MOVECHAN              = 0xf4fe10,
        .MOVEOBJ               = 0x14a8bf8,
        .MOVEARG               = 0x14ab008,
        .CHANFILT              = 0x14a7968,
        .PATARR                = 0x14aa0c8,
        .NOTEARR               = 0x11d4080,
        .NOTEDEL               = 0xf6d7d0,
        .NOTELOCK              = 0x14a96c8,
        .GRIDREFRESH           = 0x11d90e0,
        .FLPROJ                = 0x14abca8,
        .MAINOBJ               = 0x14a8750,
        .SETPROJ               = 0x10d2c90,
        .SAVEPROJ              = 0x10d5a60,
        .BUSYBEGIN             = 0x10c9860,
        .BUSYEND               = 0x10c98b0,
        .PROJNAME              = 0x15812a0,
        .ARRS                  = 0x18329d8,
        .ARRCUR                = 0x149e8b4,
        .PLFORM                = 0x14aab88,
        .PLREFRESH             = 0xd45d90,
        .HINT                  = 0x10ec570,
        .MIXNAME               = 0x11c2810,
        .MIXCOLOR              = 0x11c58a0,
        .UIUPDATE              = 0xb6a1d0,
        .MIXOBJ                = 0x14a99a0,
        .SETROUTE              = 0x11a67f0,
        .ROUTEUPD              = 0x11a5d20,
        .PATNAME               = 0x11d3960,
        .PATCOLOR              = 0x11d3e50,
        .PATREFRESH            = 0xda0a70,
        .PLTRACK               = 0x11e7940,
        .MARKADD               = 0xf70ba0,
        .MARKTYPE              = 0xf61698,
        .DYNSETLEN             = 0x417fc0,
        .MARKREFRESH           = 0xd51810,
        .MARKSORT              = 0xf70510,
        .PATLENUPD             = 0x11d4140,
        .PATMARKS              = 0x11d3500,
        .SONGLOCK              = 0x14ab2d8,
        .MODIFIED              = 0x10cefa0,
        .TSNUM                 = 0x14aaf70,
        .TSDEN                 = 0x14a9368,
        .TSSET                 = 0x125e4c0,
        .TSCTLS                = 0x125e630,
        .MSGBOX                = 0xa88770,
        .MSGBOX_CORE           = 0xa886f0,
        .PRFORM                = 0x14a9b20,
        .CURPAT                = 0x14ab580,
        .CH_SELECTED           = 0x35c,
        .CH_GRID               = 0x7bc,
        .FORM_BUSY             = 0x334c,
        .PAT_STRIDE            = 0xc0,
        .PLFORM_PATS           = 0xd0c,
        .PL_MARKSEL            = 0xd64,
        .ED_TICKSPERPX         = 0xaec,
        .ED_HSCROLL            = 0xafc,
        .PR_GRID               = 0xc40,
        .PL_GRID               = 0xd04,
        .GRID_VSCROLL          = 0x3fc,
        .MIX_STRIDE            = 0x1474,
        .MIX_SLOTS_OFF         = 0x1324,
        .MIX_ROUTE             = 0x2e4,
        .FLPROJ_LOAD_SLOT      = 0x38,
        .PATOP_CLONE_SLOT      = 0xd8,
        .PATOP_DELETE_SLOT     = 0xe0,
        .PATOP_REARRANGE_SLOT  = 0xe8,
        .PATOP_EDIT_SLOT       = 0xf0,
        .PATOP_INSERT_SLOT     = 0xf8,
        .PATOP_SPLIT_SLOT      = 0x100,
    },
#ifdef FLIM_EXPERIMENTAL_FL26
    {   // FL Studio 24.2.2.4597: tested installed engine, with its older format adapters
        .build = L"24.2.2.4597", .msgbox = 2,
        .REC                    = 0xe8dee0,
        .MUTE                   = 0x1135280,
        .MIXARR                 = 0x143b148,
        .MIXCNT                 = 0x0,
        .MAINFORM               = 0x143bd60,
        .SAVEPRESET             = 0xd78fe0,
        .LOADPRESET             = 0xd791d0,
        .HASPLUGIN              = 0x11ddb90,
        .GETPLUGIN              = 0x11df6e0,
        .INTFCLEAR              = 0x41a750,
        .ADDCHAN                = 0xe62000,
        .DELCHAN                = 0xe62810,
        .RESOLVER               = 0xe63500,
        .CHANLIST               = 0x143cb08,
        .MOVECHAN               = 0xe8a580,
        .MOVEOBJ                = 0x143be60,
        .MOVEARG                = 0x143e1d0,
        .CHANFILT               = 0x143ac08,
        .PATARR                 = 0x143d2b8,
        .NOTEARR                = 0x118be50,
        .NOTEDEL                = 0xea35d0,
        .NOTELOCK               = 0x143c900,
        .GRIDREFRESH            = 0x118ed70,
        .FLPROJ                 = 0x143ee58,
        .MAINOBJ                = 0x143b9b8,
        .SETPROJ                = 0x106ea20,
        .SAVEPROJ               = 0x107a4b0,
        .BUSYBEGIN              = 0x10657a0,
        .BUSYEND                = 0x10657f0,
        .PROJNAME               = 0x1512e70,
        .ARRS                   = 0x157bde0,
        .ARRCUR                 = 0x1431d10,
        .PLFORM                 = 0x143dd60,
        .PLREFRESH              = 0xd30840,
        .HINT                   = 0x1095e90,
        .MIXNAME                = 0x1179910,
        .MIXCOLOR               = 0x117c8f0,
        .UIUPDATE               = 0xbd4f20,
        .MIXOBJ                 = 0x143cbc8,
        .SETROUTE               = 0x1161a90,
        .ROUTEUPD               = 0x1161350,
        .PATNAME                = 0x118b740,
        .PATCOLOR               = 0x118bc30,
        .PATREFRESH             = 0xd404d0,
        .PLTRACK                = 0x119bec0,
        .MARKADD                = 0xea67c0,
        .MARKTYPE               = 0xe9b448,
        .DYNSETLEN              = 0x417fb0,
        .MARKREFRESH            = 0xcec620,
        .MARKSORT               = 0xea6220,
        .PATLENUPD              = 0x118bf00,
        .PATMARKS               = 0x118b320,
        .SONGLOCK               = 0x143e4a8,
        .MODIFIED               = 0x106ae80,
        .TSNUM                  = 0x143e140,
        .TSDEN                  = 0x143c598,
        .TSSET                  = 0x12155f0,
        .TSCTLS                 = 0x1215760,
        .MSGBOX                 = 0xa7f920,
        .MSGBOX_CORE            = 0x0,
        .PRFORM                 = 0x143cd40,
        .CURPAT                 = 0x143e730,
        .CH_SELECTED            = 0x344,
        .CH_GRID                = 0x748,
        .FORM_BUSY              = 0x2f14,
        .PAT_STRIDE             = 0x90,
        .PLFORM_PATS            = 0xcc0,
        .PL_MARKSEL             = 0xd18,
        .ED_TICKSPERPX          = 0xad4,
        .ED_HSCROLL             = 0xae4,
        .PR_GRID                = 0xc00,
        .PL_GRID                = 0xcb8,
        .GRID_VSCROLL           = 0x3f8,
        .MIX_STRIDE             = 0x8ac,
        .MIX_SLOTS_OFF          = 0x75c,
        .MIX_ROUTE              = 0x2e4,
        .FLPROJ_LOAD_SLOT       = 0x28,
        .PATOP_CLONE_SLOT       = 0xc8,
        .PATOP_DELETE_SLOT      = 0xd0,
        .PATOP_REARRANGE_SLOT   = 0xd8,
        .PATOP_EDIT_SLOT        = 0xe0,
        .PATOP_INSERT_SLOT      = 0xe8,
        .PATOP_SPLIT_SLOT       = 0xf0,
    },
    {   // FL Studio 26.1.6.5639: experimental mapping; see dev/compatibility/
        .build = L"26.1.6.5639", .msgbox = 1,
        .REC           = 0x1046540,
        .MUTE          = 0x1280680,
        .MIXARR        = 0x15e4708,
        .MIXCNT        = 0x15e6200,
        .MAINFORM      = 0x15e5418,
        .SAVEPRESET    = 0xf54600,
        .LOADPRESET    = 0xf547f0,
        .HASPLUGIN     = 0x13342e0,
        .GETPLUGIN     = 0x1335ea0,
        .INTFCLEAR     = 0x41a770,
        .ADDCHAN       = 0x1003d00,
        .DELCHAN       = 0x1004530,
        .RESOLVER      = 0x1005240,
        .CHANLIST      = 0x15e6280,
        .MOVECHAN      = 0x10422d0,
        .MOVEOBJ       = 0x15e5508,
        .MOVEARG       = 0x15e7ac8,
        .CHANFILT      = 0x15e4190,
        .PATARR        = 0x15e6b08,
        .NOTEARR       = 0x12d6200,
        .NOTEDEL       = 0x105fe80,
        .NOTELOCK      = 0x15e6070,
        .GRIDREFRESH   = 0x12db420,
        .FLPROJ        = 0x15e87f8,
        .MAINOBJ       = 0x15e5060,
        .SETPROJ       = 0x11d8e40,
        .SAVEPROJ      = 0x11db8d0,
        .BUSYBEGIN     = 0x11cf500,
        .BUSYEND       = 0x11cf550,
        .PROJNAME      = 0x16c0c98,
        .ARRS          = 0x1972b60,
        .ARRCUR        = 0x15da658,
        .PLFORM        = 0x15e7630,
        .PLREFRESH     = 0xe47e80,
        .HINT          = 0x11f11b0,
        .MIXNAME       = 0x12c33c0,
        .MIXCOLOR      = 0x12c64b0,
        .UIUPDATE      = 0xbd6930,
        .MIXOBJ        = 0x15e6340,
        .SETROUTE      = 0x12a8090,
        .ROUTEUPD      = 0x12a75c0,
        .PATNAME       = 0x12d5ae0,
        .PATCOLOR      = 0x12d5fd0,
        .PATREFRESH    = 0xea7be0,
        .PLTRACK       = 0x12eac10,
        .MARKADD       = 0x1063290,
        .MARKTYPE      = 0x1053d50,
        .DYNSETLEN     = 0x417fc0,
        .MARKREFRESH   = 0xe53a10,
        .MARKSORT      = 0x1062c00,
        .PATLENUPD     = 0x12d62c0,
        .PATMARKS      = 0x12d5680,
        .SONGLOCK      = 0x15e7da8,
        .MODIFIED      = 0x11d4ff0,
        .TSNUM         = 0x15e7a28,
        .TSDEN         = 0x15e5cd8,
        .TSSET         = 0x136a1c0,
        .TSCTLS        = 0x136a330,
        .MSGBOX        = 0x963680,
        .MSGBOX_CORE   = 0x9635f0,
        .PRFORM        = 0x15e64e0,
        .CURPAT        = 0x15e8080,
        .CH_SELECTED   = 0x32c,
        .CH_GRID       = 0x7ac,
        .FORM_BUSY     = 0x34d4,
        .PAT_STRIDE    = 0xc0,
        .PLFORM_PATS   = 0xd34,
        .PL_MARKSEL    = 0xd8c,
        .ED_TICKSPERPX = 0xb04,
        .ED_HSCROLL    = 0xb14,
        .PR_GRID       = 0xc68,
        .PL_GRID       = 0xd2c,
        .GRID_VSCROLL  = 0x3fc,
        .MIX_STRIDE    = 0x1478,
        .MIX_SLOTS_OFF = 0x134c,
        .MIX_ROUTE     = 0x394,
        .FLPROJ_LOAD_SLOT = 0x40,
        .PATOP_CLONE_SLOT = 0xe8,
        .PATOP_DELETE_SLOT = 0xf8,
        .PATOP_REARRANGE_SLOT = 0x108,
        .PATOP_EDIT_SLOT = 0x110,
        .PATOP_INSERT_SLOT = 0x118,
        .PATOP_SPLIT_SLOT = 0x120,
    },
    {   // FL Studio 26.1.7.5654: experimental mapping; see dev/compatibility/
        .build = L"26.1.7.5654", .msgbox = 1,
        .REC                 = 0x1046a70,
        .MUTE                = 0x127b9b0,
        .MIXARR              = 0x15e06a0,
        .MIXCNT              = 0x15e2198,
        .MAINFORM            = 0x15e13b8,
        .SAVEPRESET          = 0xf54570,
        .LOADPRESET          = 0xf54760,
        .HASPLUGIN           = 0x132f7c0,
        .GETPLUGIN           = 0x1331380,
        .INTFCLEAR           = 0x41a770,
        .ADDCHAN             = 0x1004230,
        .DELCHAN             = 0x1004a60,
        .RESOLVER            = 0x1005770,
        .CHANLIST            = 0x15e2218,
        .MOVECHAN            = 0x1042800,
        .MOVEOBJ             = 0x15e14a0,
        .MOVEARG             = 0x15e3a60,
        .CHANFILT            = 0x15e0128,
        .PATARR              = 0x15e2aa0,
        .NOTEARR             = 0x12d16e0,
        .NOTEDEL             = 0x10603b0,
        .NOTELOCK            = 0x15e2008,
        .GRIDREFRESH         = 0x12d6900,
        .FLPROJ              = 0x15e4790,
        .MAINOBJ             = 0x15e0ff8,
        .SETPROJ             = 0x11d9380,
        .SAVEPROJ            = 0x11dbe10,
        .BUSYBEGIN           = 0x11cf9f0,
        .BUSYEND             = 0x11cfa40,
        .PROJNAME            = 0x16bcc98,
        .ARRS                = 0x196eb60,
        .ARRCUR              = 0x15d65f0,
        .PLFORM              = 0x15e35c8,
        .PLREFRESH           = 0xe47c70,
        .HINT                = 0x11f16f0,
        .MIXNAME             = 0x12be6f0,
        .MIXCOLOR            = 0x12c17e0,
        .UIUPDATE            = 0xbd68e0,
        .MIXOBJ              = 0x15e22d8,
        .SETROUTE            = 0x12a33c0,
        .ROUTEUPD            = 0x12a28f0,
        .PATNAME             = 0x12d0fc0,
        .PATCOLOR            = 0x12d14b0,
        .PATREFRESH          = 0xea7ae0,
        .PLTRACK             = 0x12e60f0,
        .MARKADD             = 0x10637c0,
        .MARKTYPE            = 0x1054280,
        .DYNSETLEN           = 0x417fc0,
        .MARKREFRESH         = 0xe53810,
        .MARKSORT            = 0x1063130,
        .PATLENUPD           = 0x12d17a0,
        .PATMARKS            = 0x12d0b60,
        .SONGLOCK            = 0x15e3d40,
        .MODIFIED            = 0x11d5530,
        .TSNUM               = 0x15e39c0,
        .TSDEN               = 0x15e1c70,
        .TSSET               = 0x13656a0,
        .TSCTLS              = 0x1365810,
        .MSGBOX              = 0x9635b0,
        .MSGBOX_CORE         = 0x963520,
        .PRFORM              = 0x15e2478,
        .CURPAT              = 0x15e4018,
        .CH_SELECTED         = 0x32c,
        .CH_GRID             = 0x7ac,
        .FORM_BUSY           = 0x34d4,
        .PAT_STRIDE          = 0xc0,
        .PLFORM_PATS         = 0xd34,
        .PL_MARKSEL          = 0xd8c,
        .ED_TICKSPERPX       = 0xb04,
        .ED_HSCROLL          = 0xb14,
        .PR_GRID             = 0xc68,
        .PL_GRID             = 0xd2c,
        .GRID_VSCROLL        = 0x3fc,
        .MIX_STRIDE          = 0x1478,
        .MIX_SLOTS_OFF       = 0x134c,
        .MIX_ROUTE           = 0x394,
        .FLPROJ_LOAD_SLOT    = 0x40,
        .PATOP_CLONE_SLOT    = 0xe8,
        .PATOP_DELETE_SLOT   = 0xf8,
        .PATOP_REARRANGE_SLOT= 0x108,
        .PATOP_EDIT_SLOT     = 0x110,
        .PATOP_INSERT_SLOT   = 0x118,
        .PATOP_SPLIT_SLOT    = 0x120,
    },
#endif
};
static FlBuild g_fl;       // the row in use (engineMain)
#define REC_RVA      (g_fl.REC - IMG_BASE)   // ProcessRECEvent(eventId, value, flags)
#define MUTE_RVA (g_fl.MUTE - IMG_BASE) // setTrackEnabled(track, enabled: 1/0, -1 toggle)
#define MIXARR_VA (g_fl.MIXARR)     // global: pointer to mixer track array (stride 0x1474)
#define MIXCNT_VA (g_fl.MIXCNT)     // global: pointer to mixer track count (int)
#define MAINFORM_VA (g_fl.MAINFORM)     // global: pointer to FL main form pointer
#define MIX_STRIDE   (g_fl.MIX_STRIDE)
#define MIX_ENABLED  0x18          // byte: 1 = enabled (unmuted)

#define REC_UpdateValue   0x01
#define REC_GetValue      0x02
#define REC_UpdateControl 0x10
#define REC_NONE          0xffffffffu  // returned for a nonexistent target

#define MAX_CH       256
#define NSUB         4             // channel params: 0=vol 1=pan 7=on/off 8=mixer route
#define MAX_SLOTS    65536
#define HASH_SIZE    (MAX_SLOTS * 2)
#define MAX_PLUG_PARAMS 4096
#define MAX_MIX      512
#define MAX_FX_SLOTS 10
#define RESCAN_MS    2000

// REC id layout (FL ProcessRECEvent):
//   channel param        (ch << 16) | sub              sub: 0 vol, 1 pan, 7 on/off, 8 route
//   channel plugin param (ch << 16) | (0x8000 + p)
//   mixer track param    0x70000000 + (t << 22) + sub  sub: 0x1fc0 vol, 0x1fc1 pan, 0x1fc2 stereo
//   mixer effect param   0x70000000 + (((t << 6) | slot) << 16) + 0x8000 + p
// Mixer mute is not a REC param; it gets a pseudo id MUTE_ID(t) handled separately.
#define REC_PLUG_FIRST 0x8000
#define MIX_ID(t, sub)        (0x70000000u + ((uint32_t)(t) << 22) + (sub))
#define FX_ID(t, slot, p)     (0x70000000u + ((((uint32_t)(t) << 6) | (slot)) << 16) + REC_PLUG_FIRST + (p))
#define MUTE_ID(t)            (0xF0000000u | (uint32_t)(t))
#define IS_MUTE_ID(id)        (((id) & 0xFFF00000u) == 0xF0000000u)
#define POLL_MS      30
#define LOCK_IDLE_MS 600           // release a param lock after this much idle

typedef uint32_t (*rec_t)(uint32_t id, uint64_t value, uint32_t flags);

static const uint32_t SUBS[NSUB] = { 0, 1, 7, 8 };
static const uint32_t MIX_SUBS[] = { 0x1fc0, 0x1fc1, 0x1fc2 };

typedef void (*setenabled_t)(int track, int enabled);
static void retry_pending(void);
static void pend_put(uint32_t id, uint32_t v);
static void pending_channels(const int *from, int n, int deleted);
static void send_full_state(void);
static void send_notes_full(void);
static void notes_rebaseline(int channels_only);
static void proj_begin(const char *why);
static void clips_rebaseline(void);
static int  unit_before_send(const char *key, int isPat, int idx, const unsigned char *d, unsigned n);
static void unit_agreed(int isPat, int idx, const unsigned char *d, unsigned n);
static void unit_revert(const char *key);
static void units_capture_all(void);
static void hint_if_held(const char *key);
static int  closing_now(void);
static int b64val(char c);
static int  plug_lock_send(int unit, int a, int b, char *key, int cap);
static int plug_agreed_set(int unit, int a, int b, const unsigned char *d, size_t n);
static void plug_agreed_reset(int channels, int fx);
static unsigned char *plug_agreed_copy(int unit, int a, int b, size_t *n);
static void plug_agreed_channels(const int *from, int n, int deleted);
static int plug_param_blocked(uint32_t id);
static int plugin_prepare(const unsigned char *d, size_t n, int unit, unsigned char **local, size_t *localn, char *reason, size_t cap);
static void plugins_changed(void);
static void plugins_retry(void);
static void plugins_auto_tick(DWORD now);
static uint64_t plugin_retry_stamp(const unsigned char *d, size_t n, int unit);
static void fl_hint(const char *msg);
static int compat_plugin_send(void);
static void plug_revert_state(int unit, int a, int b);
static void plug_undo(const char *key, int apply);
static void meta_rebaseline(int channels_only);
static wchar_t *dstr_keep(const wchar_t *s);
static int int_after(const char *p, const char *end, const char *key, int *out);
static int compat_outgoing(const char *msg);
static void compat_fail(const char *why);
static void sharing_fail(const char *status, const char *why);
static void ws_send(const char *msg);
static void ws_send_to(const char *msg, const char *target);
static void request_state(void);
static void portable_send(const char *target);
static void portable_send_peers(void);
static void portable_start(int channels);
static void ws_send_samples(char *msg, const unsigned char *blob, size_t n);
static void samples_rewrite(unsigned char **d, size_t *n);
typedef enum { FLP_BUILD_INVALID = -1, FLP_BUILD_MATCH, FLP_BUILD_MISMATCH, FLP_BUILD_FORWARD } FlpBuildCheck;
static FlpBuildCheck flp_check_build(const unsigned char *d, size_t n, char *theirs, char *mine);

typedef struct {
    uint32_t id;
    uint32_t last;          // last value seen/applied (REC_NONE = unknown/absent)
    volatile LONG gen;      // bumped on every apply; poller discards racing reads
    int  lockedByMe;
    DWORD lastTouch;        // tick of our last local change
    int  lockedByPeer;
    int  hasUndo;           // plugin param changed while its plugin lock was still requested:
    uint32_t undo;          //   value to restore if the lock is denied
} Slot;

static Slot   g_slots[MAX_SLOTS];
static volatile LONG g_nslot = 0;
static int    g_hash[HASH_SIZE];   // slot index + 1; 0 = empty
static setenabled_t g_setEnabled = NULL;
static char  *g_flBase = NULL;
static int    g_chanPlugN[MAX_CH];
static int    g_fxN[MAX_MIX][MAX_FX_SLOTS];
static CRITICAL_SECTION g_lifecycleLock;
static volatile LONG g_netGen = 0;
static __declspec(thread) LONG g_workGen;
static __declspec(thread) int g_workBound;
static LONG session_generation(void) { return g_workBound ? g_workGen : g_netGen; }
static int session_current(void) { return !g_workBound || g_workGen == g_netGen; }
static volatile LONG g_compatReady = 0, g_compatMixed = 0, g_compatFault = 0;
static volatile LONG g_portableSync = 0, g_portableLocal = 0;
static volatile LONG g_cloudTransport = 0;
static char g_hostFlBuild[32];
static volatile LONG g_isLeader = 0;
static volatile LONG g_patDepth = 0;   // a pattern op is running (main thread; its dialogs pump messages): scans wait
static rec_t  g_rec = NULL;
static HINTERNET g_ws = NULL;    // the open WebSocket (NULL = not connected); guarded by g_sendLock
static CRITICAL_SECTION g_sendLock, g_slotLock, g_qLock;
static char   g_myId[64];
static HWND   g_mainWnd = NULL;
static HHOOK  g_hook = NULL;
static HINSTANCE g_hinst = NULL;

// ---- plugin / structure sync (FL functions, Ghidra VAs) ----
#define SAVEPRESET_VA (g_fl.SAVEPRESET)     // SavePresetFile(UnicodeString file, mask, obj, flags) -> 0 ok
#define LOADPRESET_VA (g_fl.LOADPRESET)     // LoadPresetFile(UnicodeString file, mask, obj, 0) -> 0 ok (replaces plugin)
#define HASPLUGIN_VA (g_fl.HASPLUGIN)    // HasPlugin(obj) -> bool
#define GETPLUGIN_VA (g_fl.GETPLUGIN)    // GetPlugin(obj, &intf) -> plugin type; intf is AddRef'd (must release!)
#define INTFCLEAR_VA (g_fl.INTFCLEAR)     // Delphi _IntfClear(&intf): nil it and Release
#define ADDCHAN_VA (g_fl.ADDCHAN)     // AddChannel(-1, 0, 1) -> new channel obj (appended)
#define DELCHAN_VA (g_fl.DELCHAN)     // DeleteChannel(index, 0, flags); flags 1|2 = no confirmation dialog
#define DELCHAN_FLAGS 3            // bit 2 = "already confirmed" (FL's menu sets it after its own dialog)
#define RESOLVER_VA (g_fl.RESOLVER)     // ResolveChannel(index, global, &obj): global 0 = index in the rack's filter group
#define CHANLIST_VA (g_fl.CHANLIST)    // global: pointer to channel list (items +8, count +0x10)
#define MIX_SLOTS_OFF (g_fl.MIX_SLOTS_OFF) // mixer track: 10 effect slot object pointers
#define MOVECHAN_VA (g_fl.MOVECHAN)     // ReorderChannels(**MOVEOBJ, mode, **MOVEARG, flags): FL's Alt+Up/Down + sorts
#define MOVEOBJ_VA (g_fl.MOVEOBJ)    //   first arg (pointer global, deref twice)
#define MOVEARG_VA (g_fl.MOVEARG)    //   third arg (int, deref twice; -1 seen)
#define MOVE_UP       4            //   mode 4 = move selected up, 5 = down, 1..3 = sorts
#define MOVE_FLAGS    1            //   bit 1 = close undo group; bit 2 = take selection from the rack UI (not wanted)
#define CHANFILT_VA (g_fl.CHANFILT)    // global: channel list of the rack's current filter group (same layout)
#define CH_SELECTED   (g_fl.CH_SELECTED)        // channel object: selected byte (what ReorderChannels moves)
// ---- notes (per pattern: a flat array of 24-byte records, same layout as FLP event 224) ----
#define PATARR_VA (g_fl.PATARR)    // global: pointer to the static pattern table (stride 0xC0)
#define PAT_STRIDE    (g_fl.PAT_STRIDE)
#define PAT_NOTES     0x28         // pattern record: note array object (NULL until the pattern has had notes)
#define MAX_PAT       1000         // FL caps pattern numbers at 999
#define NOTES_DATA    0x08         // note array: record pointer
#define NOTES_COUNT   0x14         //             record count (u32); element size (0x18) at +0x10
#define NOTE_SIZE     24
#define NOTE_SEL_OFS  0x13         // byte: low bits = note color, bit 0x80 = SELECTED (client-only, never synced)
#define NOTE_SEL_BIT  0x80
#define NOTEARR_VA (g_fl.NOTEARR)    // NoteArray(pattern, create) -> note array object
#define NOTEDEL_VA (g_fl.NOTEDEL)     // DeleteNote(arr, index, 0)
#define NOTEADD_VSLOT 1            // arr->vmt[1](arr, &rec): add a note (vmt[2] fills a default record)
#define NOTELOCK_VA (g_fl.NOTELOCK)    // global: CRITICAL_SECTION* FL holds while editing notes (audio thread reads them)
#define GRIDREFRESH_VA (g_fl.GRIDREFRESH)   // RefreshGrid(channel->grid at +0x7bc)
#define CH_GRID       (g_fl.CH_GRID)
#define MASK_CHAN     32           // preset mask for channels (what FL's undo uses)
#define MASK_FX       48           // preset mask for mixer slots (32 faults on a slot)

// ---- project files (FL functions / globals, Ghidra VAs) ----
#define FLPROJ_VA (g_fl.FLPROJ)    // global -> holder; *(holder + 0x10) = TFLProject object
#define FLPROJ_LOAD_SLOT (g_fl.FLPROJ_LOAD_SLOT / 8) // LoadFile(self, path, flags); flags bit 0 = "save changes?" prompt
#define MAINOBJ_VA (g_fl.MAINOBJ)    // global -> var -> main form object (what FL's own open/save code passes)
#define FORM_BUSY     (g_fl.FORM_BUSY)       // main form: busy object, non-NULL while an .flp load runs
#define SETPROJ_VA (g_fl.SETPROJ)    // SetProjectFile(form, path, path, addRecent): title, Ctrl+S target, recent list
#define SAVEPROJ_VA (g_fl.SAVEPROJ)    // SaveProjectTo(path, 0) -> bool: FL's project writer; current name unchanged
#define BUSYBEGIN_VA (g_fl.BUSYBEGIN)    // FL's open handler wraps an .flp load in these two
#define BUSYEND_VA (g_fl.BUSYEND)
#define PROJNAME_VA (g_fl.PROJNAME)    // UnicodeString global: current project file ('' = untitled)
#define WM_FL_OPENPROJ 0x566       // FL posts this to its main form to open a project (dialog, browser, drop)
// ---- playlist clips (current arrangement) ----
#define ARRS_VA (g_fl.ARRS)    // global -> arrangement pointer array (count as int64 at -8)
#define ARRCUR_VA (g_fl.ARRCUR)    // int global: current arrangement index
#define ARR_CLIPS     0x14         // arrangement: clip array object (same array family as notes)
#define CLIPS_DATA    0x08
#define CLIPS_COUNT   0x14
#define CLIP_SIZE     FLIM_CLIP_WIRE_SIZE
#define CLIP_DEL_OFS  0x04         // -1 = deleted (then purge)
#define CLIP_SEL_OFS  0x13         // bit 0x80 = SELECTED (client-only)
#define CLIP_SEL_BIT  0x80
#define CLIP_ID_OFS   0x20         // per-instance clip id (FL renumbers on add)
#define CLIPADD_VSLOT   1          // arr->vmt[1](arr, &rec) -> index (kept sorted by position)
#define CLIPPURGE_VSLOT 3          // arr->vmt[3](arr): drop records marked deleted, free their resources
#define PLFORM_VA (g_fl.PLFORM)    // global -> var -> playlist form
#define PLREFRESH_VA (g_fl.PLREFRESH) // form refresh; exact FL24 uses a grid invalidator through playlist_refresh
#define HINT_VA (g_fl.HINT)    // ShowHint(form, UnicodeString text, 0): FL's hint bar (top left)
#define PROJ_FX_MASS  3            // this many effects gone in one scan = project close, not a delete

typedef int   (*presetfile_t)(const wchar_t *file, int mask, void *obj, int flags);
typedef char  (*hasplugin_t)(void *obj);
typedef void *(*getplugin_t)(void *obj, void **inst);
typedef void  (*intfclear_t)(void **intf);
typedef void *(*addchan_t)(int a, int b, int c);
typedef void  (*delchan_t)(unsigned idx, char force, uint64_t flags);
typedef int   (*resolver_t)(int idx, char useGlobal, void **out);
typedef void  (*movechan_t)(void *obj, uint8_t mode, int arg, uint64_t flags);
typedef void *(*notearr_t)(int pattern, char create);
typedef void  (*notedel_t)(void *arr, int index, char flag);
typedef void  (*noteadd_t)(void *arr, const void *rec);
typedef void  (*gridrefresh_t)(void *grid);
typedef char  (*projload_t)(void *self, const wchar_t *path, uint8_t flags);
typedef void  (*setproj_t)(void *form, const wchar_t *p1, const wchar_t *p2, uint8_t addRecent);
typedef char  (*saveproj_t)(const wchar_t *path, uint8_t flag);
typedef void  (*formfn_t)(void *form);
typedef int   (*clipadd_t)(void *arr, const void *rec);
typedef void  (*clippurge_t)(void *arr);
typedef void  (*hint_t)(void *form, const wchar_t *text, uint8_t flag);

static presetfile_t g_savePreset, g_loadPreset;
static hasplugin_t  g_hasPlugin;
static getplugin_t  g_getPlugin;
static intfclear_t g_intfClear;
static addchan_t    g_addChannel;
static delchan_t    g_delChannel;
static resolver_t   g_resolve;
static movechan_t   g_moveChans;
static notearr_t    g_noteArr;
static notedel_t    g_noteDel;
static gridrefresh_t g_gridRefresh;

// ---- main-thread task queue ----
// Param writes are cheap and run back to back; anything that calls into FL's
// preset/channel code is "heavy" and runs one per message-loop tick (a plugin
// often needs the message loop to run between load and the next call).
enum { T_PARAM, T_SNAP, T_LOAD, T_ADDCH, T_DELCH, T_STRUCT, T_FULL, T_ORDER, T_FXCLEAR, T_FXSYNC,
       T_NOTESNAP, T_NOTES, T_NOTESYNC, T_NOTEBASE, T_PROJLOAD, T_PROJDONE, T_PROJSNAP,
       T_CLIPSNAP, T_CLIPS, T_UNITREVERT, T_HINT, T_METASNAP, T_META, T_PATOP, T_PLUGRETRY,
       T_PORTABLESEND, T_PORTABLESTART };
enum { U_CH, U_FX };
enum { SNAP_BASELINE, SNAP_IF_DIFF, SNAP_FORCE, SNAP_ADD, SNAP_COLLECT };
#define QCAP 16384
typedef struct {
    int type;
    LONG sessionGen;
    uint32_t id, v;          // T_PARAM
    LONG applyGen;          // local T_PARAM revert: reject after a remote preset load
    int unit, a, b;          // unit kind + (channel) or (track, slot)
    int mode;                // T_SNAP mode / T_LOAD: 1 = skip if identical
    char *path;              // T_LOAD / T_ADDCH: inbound .fst file (owned; deleted after use)
    char presetFl[32];
    int *order;              // T_ORDER: [n, from0..from(n-1)]; T_FXSYNC/T_NOTESYNC: bitmap;
                             // T_NOTES: note records, it->mode = count (owned)
} QItem;
static void run_task_inner(const QItem *it);
static QItem g_q[QCAP];
static int g_qh = 0, g_qt = 0;

#ifndef FLIM_LOG_MAX_BYTES
#define FLIM_LOG_MAX_BYTES (4u * 1024u * 1024u)
#endif
#define FLIM_LOG_PATH_CAP 4096
static SRWLOCK g_logLock = SRWLOCK_INIT;
static wchar_t g_logPath[FLIM_LOG_PATH_CAP];
static HANDLE g_logFile = INVALID_HANDLE_VALUE;
static int g_logInitialized;
static ULONGLONG g_logRetryAt;

static int log_absolute_path(const wchar_t *path) {
    return ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'))
        ? path[1] == L':' && (path[2] == L'\\' || path[2] == L'/')
        : path[0] == L'\\' && path[1] == L'\\';
}

static void log_path_init(void) {
    wchar_t directory[FLIM_LOG_PATH_CAP];
    DWORD n = GetEnvironmentVariableW(L"FLIM_LOG_DIR", directory, FLIM_LOG_PATH_CAP);
    g_logInitialized = 1;
    if (n && n < FLIM_LOG_PATH_CAP - 64 && log_absolute_path(directory)) {
        _snwprintf_s(g_logPath, FLIM_LOG_PATH_CAP, _TRUNCATE, L"%s%snative-%lu.log", directory,
                     directory[n - 1] == L'\\' || directory[n - 1] == L'/' ? L"" : L"\\", GetCurrentProcessId());
        return;
    }
    n = GetTempPathW(FLIM_LOG_PATH_CAP, directory);
    if (n && n < FLIM_LOG_PATH_CAP - 32)
        _snwprintf_s(g_logPath, FLIM_LOG_PATH_CAP, _TRUNCATE, L"%sflim_engine.log", directory);
}

// Do not retain credential-bearing payloads if a future diagnostic accidentally includes one.
static int log_has_credentials(const char *text) {
    static const char *const keys[] = {
        "\"password\"", "\"blob\"", "\"owner\"", "\"token\"", "\"authorization\"",
        "\"hostToken\"", "\"joinToken\"", "\"host_token\"", "\"join_token\"", "\"blobKey\"", "\"file_peer\"",
        "password=", "password:", "owner_key=", "owner_key:", "token=", "token:", "bearer "
    };
    const char *p; size_t k;
    for (p = text; *p; p++)
        for (k = 0; k < sizeof(keys) / sizeof(keys[0]); k++)
            if (!_strnicmp(p, keys[k], strlen(keys[k]))) return 1;
    return 0;
}

static void log_close_file(void) {
    if (g_logFile != INVALID_HANDLE_VALUE) CloseHandle(g_logFile);
    g_logFile = INVALID_HANDLE_VALUE;
}

static int log_rotate(void) {
    wchar_t first[FLIM_LOG_PATH_CAP], second[FLIM_LOG_PATH_CAP];
    log_close_file();
    _snwprintf_s(first, FLIM_LOG_PATH_CAP, _TRUNCATE, L"%s.1", g_logPath);
    _snwprintf_s(second, FLIM_LOG_PATH_CAP, _TRUNCATE, L"%s.2", g_logPath);
    if (GetFileAttributesW(first) != INVALID_FILE_ATTRIBUTES && !MoveFileExW(first, second, MOVEFILE_REPLACE_EXISTING)) return 0;
    return MoveFileExW(g_logPath, first, MOVEFILE_REPLACE_EXISTING) != 0;
}

static int log_open_file(void) {
    if (g_logFile == INVALID_HANDLE_VALUE)
        g_logFile = CreateFileW(g_logPath, FILE_APPEND_DATA | FILE_READ_ATTRIBUTES,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    return g_logFile != INVALID_HANDLE_VALUE;
}

static void logmsg(const char *fmt, ...) {
    char message[6144], line[6400], build[48] = "unknown";
    SYSTEMTIME time; LARGE_INTEGER size;
    DWORD written, savedError = GetLastError();
    size_t length, i;
    va_list args;
    va_start(args, fmt); _vsnprintf_s(message, sizeof(message), _TRUNCATE, fmt, args); va_end(args);
    if (log_has_credentials(message)) strcpy_s(message, sizeof(message), "[credential-bearing diagnostic omitted]");
    for (i = 0; message[i]; i++) if ((unsigned char)message[i] < 32) message[i] = ' ';
    if (g_fl.build) WideCharToMultiByte(CP_UTF8, 0, g_fl.build, -1, build, sizeof(build), NULL, NULL);
    GetLocalTime(&time);
    _snprintf_s(line, sizeof(line), _TRUNCATE, "%04u-%02u-%02u %02u:%02u:%02u.%03u [%lu] %s [tid=%lu fl=%s]\n",
                time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond, time.wMilliseconds,
                GetCurrentProcessId(), message, GetCurrentThreadId(), build);
    length = strlen(line);
    AcquireSRWLockExclusive(&g_logLock);
    if (!g_logInitialized) log_path_init();
    if (!g_logPath[0] || GetTickCount64() < g_logRetryAt) goto done;
    if (length > FLIM_LOG_MAX_BYTES || !log_open_file() || !GetFileSizeEx(g_logFile, &size)) goto failed;
    if ((ULONGLONG)size.QuadPart + length > FLIM_LOG_MAX_BYTES) {
        if (!log_rotate() || !log_open_file()) goto failed;
    }
    if (!WriteFile(g_logFile, line, (DWORD)length, &written, NULL) || written != length) goto failed;
    goto done;
failed:
    log_close_file();
    g_logRetryAt = GetTickCount64() + 1000;
done:
    ReleaseSRWLockExclusive(&g_logLock);
    SetLastError(savedError);
}

static unsigned hash_id(uint32_t id) { return (id * 2654435761u) % HASH_SIZE; }

static Slot *slot_by_id(uint32_t id) {
    Slot *r = NULL;
    unsigned h = hash_id(id);
    EnterCriticalSection(&g_slotLock);
    while (g_hash[h]) {
        if (g_slots[g_hash[h] - 1].id == id) { r = &g_slots[g_hash[h] - 1]; break; }
        h = (h + 1) % HASH_SIZE;
    }
    LeaveCriticalSection(&g_slotLock);
    return r;
}

static int mix_count(void) {
    int n;
    if (flim_profile_fl24(&g_fl)) return 126;
    __try { n = **(int **)(g_flBase + (MIXCNT_VA - IMG_BASE)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return n < 0 ? 0 : (n > MAX_MIX ? MAX_MIX : n);
}

// ProcessRECEvent dereferences FL's main form (*(*0x1497368) + 0xf30) first thing;
// it is null until FL has finished creating its UI. Calling REC before that crashes FL.
static int fl_ready(void) {
    __try {
        char **pl = *(char ***)(g_flBase + (MAINFORM_VA - IMG_BASE));
        if (!pl || !*pl) return 0;
        return *(void **)(*pl + (flim_profile_fl24(&g_fl) ? 0xf38 : 0xf30)) != NULL;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// Current value of any synced id (REC param or pseudo id). REC_NONE if absent.
// SEH-guarded so a bad moment inside FL (e.g. mid project load) can't take FL down.
static uint32_t local_rec_id(uint32_t id) {
    if (flim_profile_fl24(&g_fl) && id >= 0x70000000u && id < 0x90000000u)
        return id - 0x50000000u;
    return id;
}

static int param_id_with_limit(uint32_t id, unsigned tracks) {
    if (IS_MUTE_ID(id)) return (id & 0xFFFFFu) < tracks;
    if (id < 0x70000000u) return (id >> 16) < MAX_CH;
    uint32_t mixer = id - 0x70000000u;
    return (mixer >> 22) < tracks &&
           ((mixer >> 16) & 63u) < MAX_FX_SLOTS;
}
static int param_id_in_range(uint32_t id) { return param_id_with_limit(id, (unsigned)mix_count()); }

static uint32_t local_rec_result(uint32_t value) {
    return flim_profile_fl24(&g_fl) && value == 0x7fffffffu ? REC_NONE : value;
}

static uint32_t read_value(uint32_t id) {
    if (!param_id_in_range(id)) return REC_NONE;
    __try {
        if (IS_MUTE_ID(id)) {
            int t = (int)(id & 0xFFFFF);
            if (t >= mix_count()) return REC_NONE;
            char *arr = *(char **)(g_flBase + (MIXARR_VA - IMG_BASE));
            return arr[(size_t)t * MIX_STRIDE + MIX_ENABLED] ? 1u : 0u;
        }
        return local_rec_result(g_rec(local_rec_id(id), 0, REC_GetValue));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return REC_NONE;
    }
}

// Must run on FL's main thread.
static uint32_t write_value(uint32_t id, uint32_t v) {
    if (!param_id_in_range(id)) return REC_NONE;
    __try {
        if (IS_MUTE_ID(id)) {
            g_setEnabled((int)(id & 0xFFFFF), v ? 1 : 0);
            return read_value(id);
        }
        return local_rec_result(g_rec(local_rec_id(id), v, REC_UpdateValue | REC_UpdateControl));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        logmsg("APPLY faulted id=0x%08x", id);
        return REC_NONE;
    }
}

// Register an id for syncing; returns 1 if it exists in FL (value != REC_NONE).
static int add_slot(uint32_t id) {
    if (slot_by_id(id)) return 1;
    uint32_t v = read_value(id);
    if (v == REC_NONE) return 0;
    EnterCriticalSection(&g_slotLock);
    if (g_nslot < MAX_SLOTS) {
        Slot *s = &g_slots[g_nslot];
        memset(s, 0, sizeof(*s));
        s->id = id;
        s->last = v;
        unsigned h = hash_id(id);
        while (g_hash[h]) h = (h + 1) % HASH_SIZE;
        g_hash[h] = g_nslot + 1;
        InterlockedIncrement(&g_nslot);   // publish after the slot is filled
    }
    LeaveCriticalSection(&g_slotLock);
    return 1;
}

// Discover channels, plugins and mixer slots; extend param ranges that grew.
// Cheap enough to run every few seconds (only probes past known ranges).
static void rescan(void) {
    LONG before = g_nslot;
    int c, k, t, sl;
    for (c = 0; c < MAX_CH; c++) {
        if (read_value((uint32_t)c << 16) == REC_NONE) continue;   // no such channel
        for (k = 0; k < NSUB; k++) add_slot(((uint32_t)c << 16) | SUBS[k]);
        while (g_chanPlugN[c] < MAX_PLUG_PARAMS &&
               add_slot(((uint32_t)c << 16) | (REC_PLUG_FIRST + g_chanPlugN[c])))
            g_chanPlugN[c]++;
    }
    int nm = mix_count();
    for (t = 0; t < nm; t++) {
        for (k = 0; k < (int)(sizeof(MIX_SUBS) / sizeof(MIX_SUBS[0])); k++) add_slot(MIX_ID(t, MIX_SUBS[k]));
        add_slot(MUTE_ID(t));
        for (sl = 0; sl < MAX_FX_SLOTS; sl++)
            while (g_fxN[t][sl] < MAX_PLUG_PARAMS && add_slot(FX_ID(t, sl, g_fxN[t][sl])))
                g_fxN[t][sl]++;
    }
    if (g_nslot != before)
        logmsg("rescan: watching %ld params (+%ld), mixer tracks=%d", g_nslot, g_nslot - before, nm);
}

// ---------------- websocket ----------------
static void b64enc(const unsigned char *in, int n, char *out) {
    static const char *T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, o = 0;
    for (i = 0; i < n; i += 3) {
        int a = in[i], b = (i + 1 < n) ? in[i + 1] : 0, c = (i + 2 < n) ? in[i + 2] : 0;
        out[o++] = T[a >> 2];
        out[o++] = T[((a & 3) << 4) | (b >> 4)];
        out[o++] = (i + 1 < n) ? T[((b & 15) << 2) | (c >> 6)] : '=';
        out[o++] = (i + 2 < n) ? T[c & 63] : '=';
    }
    out[o] = 0;
}

// One text message, now. WinHTTP allows one send at a time per socket: g_sendLock serializes.
// Everything else calls ws_send (samples section), which keeps ops behind ones waiting for samples.
static void ws_send_now(const char *msg, LONG generation) {
    DWORD e = 0;
    if (generation != g_netGen || g_compatFault || !compat_outgoing(msg)) return;
    EnterCriticalSection(&g_sendLock);
    if (generation == g_netGen && !g_compatFault && g_ws) e = WinHttpWebSocketSend(g_ws, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE, (PVOID)msg, (DWORD)strlen(msg));
    LeaveCriticalSection(&g_sendLock);
    if (e) logmsg("send failed (%lu)", e);
}

// Server address as typed in the Connect dialog:
//   wss://host[:port][/path], ws://..., https:// / http:// (same as wss / ws), or host[:port].
// A bare host means wss on 443; localhost, 127.x or an explicit non-443 port mean plain ws.
typedef struct { int secure; wchar_t host[256]; INTERNET_PORT port; wchar_t path[512]; char shown[300]; } NetUrl;
#define FLIM_SESSION_CAP 9

static int session_valid(const char *session) {
    size_t i, n = strlen(session);
    if (n != 2 && n != 8) return 0;
    for (i = 0; i < n; i++) if (session[i] < '0' || session[i] > '9') return 0;
    return 1;
}

static int parse_url(const char *in, NetUrl *u) {
    char buf[800], pathA[512] = "/", *p, *h, *slash, *colon;
    int scheme = -1;                                    // 1 = TLS, 0 = plain, -1 = not given
    size_t n;
    memset(u, 0, sizeof(*u));
    while (*in == ' ' || *in == '\t') in++;
    if (strlen(in) >= sizeof(buf)) return 0;
    strcpy_s(buf, sizeof(buf), in);
    n = strlen(buf);
    while (n && (unsigned char)buf[n - 1] <= ' ') buf[--n] = 0;
    p = buf;
    if (_strnicmp(p, "wss://", 6) == 0) { scheme = 1; p += 6; }
    else if (_strnicmp(p, "https://", 8) == 0) { scheme = 1; p += 8; }
    else if (_strnicmp(p, "ws://", 5) == 0) { scheme = 0; p += 5; }
    else if (_strnicmp(p, "http://", 7) == 0) { scheme = 0; p += 7; }
    else if (strstr(p, "://")) return 0;
    h = p;
    slash = strchr(h, '/');
    if (slash) {
        if (strlen(slash) >= sizeof(pathA)) return 0;
        strcpy_s(pathA, sizeof(pathA), slash); *slash = 0;
    }
    for (p = pathA; *p; p++)
        if ((unsigned char)*p <= ' ' || (unsigned char)*p >= 127 || strchr("?#\\%", *p)) return 0;
    colon = strrchr(h, ':');
    if (colon) {
        char *e; long port;
        for (p = colon + 1; *p; p++) if (*p < '0' || *p > '9') return 0;
        port = strtol(colon + 1, &e, 10);
        if (*e || port <= 0 || port > 65535) return 0;
        u->port = (INTERNET_PORT)port; *colon = 0;
    }
    if (!*h || strlen(h) > 253) return 0;
    for (p = h; *p; p++) if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '-' || *p == '_')) return 0;
    if (scheme < 0) {
        int local = _stricmp(h, "localhost") == 0 || strncmp(h, "127.", 4) == 0;
        scheme = ((u->port && u->port != 443) || local) ? 0 : 1;
        if (local && !u->port) u->port = 8080;
    }
    u->secure = scheme;
    if (!u->port) u->port = scheme ? 443 : 80;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, h, -1, u->host, 256) ||
        !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, pathA, -1, u->path, 512)) return 0;
    strcpy_s(u->shown, sizeof(u->shown), h);              // status text: host[:port][/path]
    if (u->port != (scheme ? 443 : 80)) sprintf_s(u->shown + strlen(u->shown), sizeof(u->shown) - strlen(u->shown), ":%u", u->port);
    if (strlen(u->shown) + strlen(pathA) >= sizeof(u->shown)) return 0;
    if (pathA[1]) strcat_s(u->shown, sizeof(u->shown), pathA);
    return 1;
}

static void url_origin(NetUrl *u) {
    char *slash = strchr(u->shown, '/');
    if (slash) *slash = 0;
}

static void url_root(NetUrl *u) {
    url_origin(u);
    wcscpy_s(u->path, 512, L"/");
}

// Legacy slots use the root socket; desktop rooms use a separate room path.
static int parse_link(const char *in, NetUrl *u, char sess[FLIM_SESSION_CAP]) {
    const wchar_t *p;
    int n = 0, room;
    sess[0] = 0;
    if (!parse_url(in, u)) return 0;
    room = !wcsncmp(u->path, L"/room/", 6);
    if (room) {
        p = u->path + 6;
        while (p[n] >= L'0' && p[n] <= L'9') n++;
        if (n != 8 || (p[n] && !(p[n] == L'/' && !p[n + 1]))) return 0;
        for (n = 0; n < 8; n++) sess[n] = (char)p[n];
        sess[8] = 0;
        u->path[14] = 0;
        url_origin(u);
        return 1;
    }
    p = u->path[0] == L'/' ? u->path + 1 : u->path;
    while (p[n] >= L'0' && p[n] <= L'9') n++;
    if (n < 1 || n > 2 || (p[n] && !(p[n] == L'/' && !p[n + 1]))) return 0;
    sprintf_s(sess, FLIM_SESSION_CAP, "%02d", _wtoi(p));
    url_root(u);
    return 1;
}

static int parse_host(const char *in, NetUrl *u) {
    char room[FLIM_SESSION_CAP];
    if (!parse_url(in, u)) return 0;
    if (!wcsncmp(u->path, L"/room/", 6)) return parse_link(in, u, room);
    if (wcscmp(u->path, L"/")) return 0;
    url_root(u);
    return 1;
}

static int welcome_session(const char *message, const NetUrl *u, char session[FLIM_SESSION_CAP]) {
    FlJson root = { message, strlen(message) }, value;
    int i, room = !wcsncmp(u->path, L"/room/", 6);
    if (!fj_get(root, "session", &value) || !fj_text(value, session, FLIM_SESSION_CAP) ||
        !session_valid(session) || strlen(session) != (room ? 8u : 2u)) return 0;
    if (room) for (i = 0; i < 8; i++) if (u->path[6 + i] != (wchar_t)session[i]) return 0;
    return 1;
}

// The link people paste into Connect.
static void session_link(const NetUrl *u, const char *sess, char *out, int cap) {
    sprintf_s(out, cap, "%s://%s/%s%s", u->secure ? "https" : "ws", u->shown,
              strlen(sess) == 8 ? "room/" : "", sess);
}

typedef struct { HINTERNET ses, con, ws; } NetConn;

static void net_close_handles(NetConn *c) {
    if (c->ws) WinHttpCloseHandle(c->ws);
    if (c->con) WinHttpCloseHandle(c->con);
    if (c->ses) WinHttpCloseHandle(c->ses);
    memset(c, 0, sizeof(*c));
}

static void net_error_text(DWORD e, const NetUrl *u, char *out, int cap) {
    switch (e) {
    case ERROR_WINHTTP_NAME_NOT_RESOLVED: strcpy_s(out, cap, "server not found (check the URL)"); break;
    case ERROR_WINHTTP_CANNOT_CONNECT:    strcpy_s(out, cap, "nothing answers at that address"); break;
    case ERROR_WINHTTP_TIMEOUT:           strcpy_s(out, cap, "timed out"); break;
    case ERROR_WINHTTP_SECURE_FAILURE:
        strcpy_s(out, cap, u->secure ? "secure connection failed (a local server needs ws://)" : "secure connection failed");
        break;
    case ERROR_WINHTTP_INVALID_SERVER_RESPONSE:
        strcpy_s(out, cap, u->secure ? "bad server response" : "bad server response (try wss://)");
        break;
    default: sprintf_s(out, cap, "network error %lu", e);
    }
}

// Open a WebSocket to the server (blocking). Returns 1 with c->ws set, or 0 + err.
static int ws_open(const NetUrl *u, NetConn *c, char *err, int errcap) {
    HINTERNET req = NULL;
    DWORD status = 0, sl = sizeof(status);
    memset(c, 0, sizeof(*c));
    c->ses = WinHttpOpen(L"flim/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!c->ses)   // before Windows 8.1
        c->ses = WinHttpOpen(L"flim/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!c->ses) goto fail;
    WinHttpSetTimeouts(c->ses, 0, 15000, 30000, 30000);          // resolve, connect, send, handshake reply
    c->con = WinHttpConnect(c->ses, u->host, u->port, 0);
    if (!c->con) goto fail;
    req = WinHttpOpenRequest(c->con, L"GET", u->path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                             u->secure ? WINHTTP_FLAG_SECURE : 0);
    if (!req) goto fail;
    if (!WinHttpSetOption(req, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0)) goto fail;
    if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0)) goto fail;
    if (!WinHttpReceiveResponse(req, NULL)) goto fail;
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                        &status, &sl, WINHTTP_NO_HEADER_INDEX);
    if (status != 101) { sprintf_s(err, errcap, "not a flim server (HTTP %lu)", status); goto out; }
    c->ws = WinHttpWebSocketCompleteUpgrade(req, 0);
    if (!c->ws) goto fail;
    WinHttpCloseHandle(req);      // idle connections are fine: the server pings every 15 s
    return 1;
fail:
    net_error_text(GetLastError(), u, err, errcap);
out:
    if (req) WinHttpCloseHandle(req);
    net_close_handles(c);
    return 0;
}

// ---------------- main-thread task queue ----------------
static void discard_task(const QItem *it) {
    if (it->type == T_LOAD || it->type == T_ADDCH) { if (it->path) { DeleteFileA(it->path); free(it->path); } }
    else if (it->type == T_UNITREVERT || it->type == T_PROJLOAD || it->type == T_HINT || it->type == T_META || it->type == T_PATOP || it->type == T_PORTABLESEND) free(it->path);
    else if (it->type == T_ORDER || it->type == T_FXSYNC || it->type == T_NOTES || it->type == T_NOTESYNC || it->type == T_CLIPS) free(it->order);
}

static void enqueue(const QItem *it) {
    LONG generation = session_generation();
    int overflow = 0;
    if (generation != g_netGen || g_compatFault) { discard_task(it); return; }
    if (((it->type == T_LOAD || it->type == T_ADDCH || it->type == T_UNITREVERT ||
          it->type == T_PROJLOAD || it->type == T_META || it->type == T_PATOP || it->type == T_PORTABLESEND) && !it->path) ||
        ((it->type == T_ORDER || it->type == T_FXSYNC || it->type == T_NOTESYNC ||
          ((it->type == T_NOTES || it->type == T_CLIPS) && it->mode)) && !it->order)) {
        discard_task(it);
        sharing_fail("Shared edit: session stopped", "There is not enough memory to queue the shared edit.");
        return;
    }
    if (it->type == T_HINT && !it->path) return;
    EnterCriticalSection(&g_qLock);
    if (it->type == T_NOTESNAP || it->type == T_CLIPSNAP || it->type == T_PLUGRETRY) {
        int i;
        for (i = g_qh; i != g_qt; i = (i + 1) % QCAP) {
            const QItem *q = &g_q[i];
            if (q->sessionGen == generation && q->type == it->type && q->a == it->a) {
                LeaveCriticalSection(&g_qLock);
                return;
            }
        }
    }
    if (it->type == T_LOAD && g_qh != g_qt) {
        // Only adjacent loads can replace each other: intervening edits may change the target.
        QItem *q = &g_q[(g_qt + QCAP - 1) % QCAP];
        if (q->sessionGen == generation && q->type == T_LOAD && q->unit == it->unit && q->a == it->a && q->b == it->b) {
                DeleteFileA(q->path); free(q->path);
                q->path = it->path; q->mode = it->mode;
                strcpy_s(q->presetFl, sizeof(q->presetFl), it->presetFl);
                LeaveCriticalSection(&g_qLock);
                logmsg("LOAD coalesced unit=%d %d/%d", it->unit, it->a, it->b);
                return;
        }
    }
    if (it->type == T_PARAM && g_qh != g_qt) {
        QItem *tail = &g_q[(g_qt + QCAP - 1) % QCAP];
        if (tail->sessionGen == generation && tail->type == T_PARAM && tail->id == it->id &&
            tail->mode == it->mode && (!it->mode || tail->applyGen == it->applyGen)) {
            tail->v = it->v; LeaveCriticalSection(&g_qLock); return;
        }
    }
    int nt = (g_qt + 1) % QCAP;
    if (nt != g_qh) { g_q[g_qt] = *it; g_q[g_qt].sessionGen = generation; g_qt = nt; }
    else {
        discard_task(it);
        // Scanners retry snapshot requests; received mutations cannot safely be dropped.
        overflow = it->type != T_NOTESNAP && it->type != T_CLIPSNAP && it->type != T_PLUGRETRY;
    }
    LeaveCriticalSection(&g_qLock);
    if (overflow) {
        sharing_fail("Edit backlog: session stopped", "FL Studio could not apply shared edits fast enough. Reconnect and resync before continuing to share.");
        return;
    }
    if (g_mainWnd) PostMessageW(g_mainWnd, WM_NULL, 0, 0); // wake the main thread
}

static void enqueue_apply(uint32_t id, uint32_t v) {
    QItem it; memset(&it, 0, sizeof(it));
    it.type = T_PARAM; it.id = id; it.v = v;
    enqueue(&it);
}

static void enqueue_unit(int type, int unit, int a, int b, int mode, char *path) {
    QItem it; memset(&it, 0, sizeof(it));
    it.type = type; it.unit = unit; it.a = a; it.b = b; it.mode = mode; it.path = path;
    enqueue(&it);
}

// ---------------- plugin / structure sync ----------------
// A "unit" is one channel or one mixer effect slot. Its full plugin state
// (identity + preset/chunk) travels as an .fst produced by FL's own preset
// saver and is applied with FL's preset loader on the other side.
typedef struct {
    void *inst;              // plugin instance seen last (identity; NULL = none)
    uint64_t hash;           // baseline state hash (0 = unknown)
    DWORD lastAct;           // last local param activity (0 = idle)
    int burst;               // a preset-sized param burst happened in this activity
    DWORD identAt;           // identity changed locally at (send after settle)
    DWORD addAt;             // channel appended locally at (send chan.add after settle)
    DWORD suppressUntil;     // remote state being applied: ignore local param changes
    DWORD absorbUntil;       // identity changes until then come from our own apply
    DWORD baselineAt;        // take a silent baseline at this tick
    DWORD baseAt;            // when the current hash baseline was taken
    volatile LONG unavailable; // keep the remote preset; never share a local placeholder
    uint64_t retryStamp;
    char presetFl[32];
    volatile LONG applyGen;  // odd throughout a remote load; even when complete
} Unit;

#define BURST_PARAMS     8       // params of one unit changing in one poll tick = preset load
#define SETTLE_ACT_MS    1000    // quiet time after param activity before re-hashing
#define SETTLE_IDENT_MS  1500    // let a new/replaced plugin finish loading before saving it
#define SUPPRESS_MS      600     // after applying remote state: late async param updates from the plugin
#define ABSORB_MS        2000    // identity changes this soon after our own apply are ours
#define REBASE_MS        1500    // silent re-baseline of a unit this long after a remote apply
#define INPUT_RECENT_MS  5000    // "someone is using FL": gate for sweeps and state sends
#define SWEEP_MS         700     // one round-robin state check per this interval
#define STRUCT_MS        500     // channel list / plugin identity scan interval

static Unit g_chU[MAX_CH];
static Unit g_fxU[MAX_MIX][MAX_FX_SLOTS];
static volatile LONG g_pluginMissing;
static volatile LONG g_pluginRetryable;
static void *g_chKnown[MAX_CH];
static int   g_nChKnown = -1;
static volatile LONG g_structGen = 0;     // bumped when channel indices shift
static volatile DWORD g_lastInput = 0;    // last local mouse/keyboard input (main thread queue)
static char  g_tmpDir[MAX_PATH];
static char  g_fxDeletePreset[MAX_PATH];  // <FL>\Data\System\(delete) effect.fst: what FL's own Delete loads into a slot
static volatile LONG g_tmpSeq = 0;

static Unit *unit_ptr(int unit, int a, int b) {
    if (unit == U_CH) return (a >= 0 && a < MAX_CH) ? &g_chU[a] : NULL;
    return (a >= 0 && a < MAX_MIX && b >= 0 && b < MAX_FX_SLOTS) ? &g_fxU[a][b] : NULL;
}

// Unit a REC id belongs to (for activity tracking); returns 0 if none.
static int unit_of_id(uint32_t id, int *unit, int *a, int *b) {
    if (IS_MUTE_ID(id)) return 0;
    if (id < 0x70000000u) { *unit = U_CH; *a = (int)(id >> 16); *b = 0; return *a < MAX_CH; }
    if ((id & 0xFFFF) < REC_PLUG_FIRST) return 0;            // mixer track vol/pan/stereo
    uint32_t ts = (id - 0x70000000u) >> 16;
    *unit = U_FX; *a = (int)(ts >> 6); *b = (int)(ts & 63);
    return *a < MAX_MIX && *b < MAX_FX_SLOTS;
}

static Unit *param_unit(uint32_t id) {
    int unit, a, b;
    return unit_of_id(id, &unit, &a, &b) ? unit_ptr(unit, a, b) : NULL;
}

static int unit_applying(const Unit *u, DWORD now) {
    return u && ((u->applyGen & 1) || (u->suppressUntil && (LONG)(now - u->suppressUntil) < 0));
}

static int unit_poll_current(const Unit *u, LONG gen, DWORD now) {
    return !u || (u->applyGen == gen && !unit_applying(u, now));
}

static void enqueue_local_revert(uint32_t id, uint32_t v, LONG applyGen) {
    QItem it; memset(&it, 0, sizeof(it));
    it.type = T_PARAM; it.id = id; it.v = v; it.mode = 1; it.applyGen = applyGen;
    enqueue(&it);
}

// Delphi x64 UnicodeString with refcount -1 (a "literal"): FL copies rather than
// references it, so we can free it after the call.
static wchar_t *dstr_new(const char *s) {
    int count = s ? MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0) : 0;
    unsigned char *m;
    if (!count) return NULL;
    m = (unsigned char *)calloc(1, 16 + (size_t)count * sizeof(wchar_t));
    if (!m) return NULL;
    *(uint16_t *)(m + 4) = 1200; *(uint16_t *)(m + 6) = 2;
    *(int32_t *)(m + 8) = -1;    *(int32_t *)(m + 12) = count - 1;
    wchar_t *w = (wchar_t *)(m + 16);
    if (!MultiByteToWideChar(CP_ACP, 0, s, -1, w, count)) { free(m); return NULL; }
    return w;
}
static void dstr_free(wchar_t *w) { if (w) free((unsigned char *)w - 16); }

static void *chan_obj(int i) {
    void *o = NULL;
    __try { if (!g_resolve(i, 1, &o)) o = NULL; } __except (EXCEPTION_EXECUTE_HANDLER) { o = NULL; }   // i: full channel list
    return o;
}
static void *fx_obj(int t, int s) {
    if (t < 0 || t >= mix_count() || s < 0 || s >= MAX_FX_SLOTS) return NULL;
    __try {
        char *arr = *(char **)(g_flBase + (MIXARR_VA - IMG_BASE));
        return *(void **)(arr + (size_t)t * MIX_STRIDE + MIX_SLOTS_OFF + (size_t)s * 8);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return NULL; }
}
static void *unit_obj(int unit, int a, int b) { return unit == U_CH ? chan_obj(a) : fx_obj(a, b); }
static int   unit_mask(int unit) { return unit == U_CH ? MASK_CHAN : MASK_FX; }

// Identity token of the plugin in obj (NULL = none). GetPlugin hands out an
// AddRef'd interface; it must be released or the plugin can never be destroyed
// (deleting its channel then hangs inside the plugin's teardown).
static void *plugin_inst(void *obj) {
    void *intf = NULL, *id = NULL;
    if (!obj) return NULL;
    __try {
        if (g_hasPlugin(obj)) g_getPlugin(obj, &intf);
        id = intf;
        if (intf) g_intfClear(&intf);
    } __except (EXCEPTION_EXECUTE_HANDLER) { id = NULL; }
    return id;
}

static int chan_list(void ***items) {
    __try {
        char *list = **(char ***)(g_flBase + (CHANLIST_VA - IMG_BASE));
        *items = *(void ***)(list + 8);
        int n = *(int *)(list + 0x10);
        return n < 0 ? 0 : (n > MAX_CH ? MAX_CH : n);
    } __except (EXCEPTION_EXECUTE_HANDLER) { *items = NULL; return 0; }
}

static int chan_list_filtered(void ***items) {
    __try {
        char *list = **(char ***)(g_flBase + (CHANFILT_VA - IMG_BASE));
        *items = *(void ***)(list + 8);
        int n = *(int *)(list + 0x10);
        return n < 0 ? 0 : (n > MAX_CH ? MAX_CH : n);
    } __except (EXCEPTION_EXECUTE_HANDLER) { *items = NULL; return 0; }
}

static uint64_t fnv64(const unsigned char *p, size_t n) {
    uint64_t h = 1469598103934665603ull;
    size_t i;
    for (i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ull; }
    return h ? h : 1;
}

// Hash of a saved .fst, skipping the 14-byte "FLhd" header: it embeds the
// project's channel count, which would make every unit look changed on add/delete.
static uint64_t state_hash(const unsigned char *d, size_t n) {
    if (n > 14 && memcmp(d, "FLhd", 4) == 0) return fnv64(d + 14, n - 14);
    return fnv64(d, n);
}

static unsigned char *read_file_checked(FILE *f, size_t *n) {
    unsigned char *buf = NULL;
    __int64 size;
    *n = 0;
    if (_fseeki64(f, 0, SEEK_END) || (size = _ftelli64(f)) < 0) goto failed;
    if ((uint64_t)size > FLIM_CLOUD_MAX) {
        sharing_fail("Shared file: session stopped", "The shared project or plugin state exceeds the 64 MiB file limit.");
        goto failed;
    }
    if (_fseeki64(f, 0, SEEK_SET)) goto failed;
    buf = (unsigned char *)malloc(size ? (size_t)size : 1);
    if (!buf || fread(buf, 1, (size_t)size, f) != (size_t)size || ferror(f) || fgetc(f) != EOF || ferror(f)) goto failed;
    if (fclose(f)) { free(buf); return NULL; }
    *n = (size_t)size;
    return buf;
failed:
    free(buf); fclose(f); return NULL;
}

static unsigned char *read_file(const char *path, size_t *n) {
    FILE *f = NULL;
    *n = 0;
    if (!path || fopen_s(&f, path, "rb") != 0 || !f) return NULL;
    return read_file_checked(f, n);
}

static char *tmp_path(const char *tag) {
    char *p = (char *)malloc(MAX_PATH);
    if (!p) { sharing_fail("Shared plugin: session stopped", "There is not enough memory to prepare the shared plugin file."); return NULL; }
    if (_snprintf_s(p, MAX_PATH, _TRUNCATE, "%s\\%s_%ld.fst", g_tmpDir, tag, InterlockedIncrement(&g_tmpSeq)) < 0) {
        free(p); sharing_fail("Shared plugin: sharing paused", "The temporary folder path is too long to prepare this preset. Choose a shorter TEMP folder before reconnecting."); return NULL;
    }
    return p;
}

// Save a unit's full state with FL's preset saver. Main thread only.
// Returns malloc'd bytes (caller frees) or NULL (empty slot / failure).
static unsigned char *unit_save(int unit, int a, int b, size_t *n) {
    void *obj = unit_obj(unit, a, b);
    unsigned char *data;
    *n = 0;
    if (!obj) return NULL;
    if (unit == U_FX && !plugin_inst(obj)) return NULL;     // never save an empty slot
    char path[MAX_PATH];
    if (strlen(g_tmpDir) + 10 >= sizeof(path)) {
        sharing_fail("Shared plugin: session stopped", "The temporary folder path is too long to save a complete plugin snapshot.");
        return NULL;
    }
    sprintf_s(path, sizeof(path), "%s\\snap.fst", g_tmpDir);
    DeleteFileA(path);
    wchar_t *w = dstr_new(path);
    int r = -1;
    if (!w) {
        sharing_fail("Shared plugin: session stopped", "There is not enough memory to save a complete plugin snapshot.");
        return NULL;
    }
    __try { r = g_savePreset(w, unit_mask(unit), obj, 1); }
    __except (EXCEPTION_EXECUTE_HANDLER) { logmsg("SAVE faulted unit=%d %d/%d", unit, a, b); r = -1; }
    dstr_free(w);
    data = r == 0 ? read_file(path, n) : NULL;
    if (data && !*n) { free(data); data = NULL; }
    if (!data) sharing_fail("Shared plugin: session stopped", "FL Studio could not save or read a complete plugin snapshot. Check available disk space and the temporary folder before reconnecting.");
    return data;
}

static void b64enc(const unsigned char *in, int n, char *out);

// Serialize {"unit":"ch","ch":i | "unit":"fx","trk":t,"slot":s, "data":"<b64>"} fields.
static char *unit_json_fields(int unit, int a, int b, const unsigned char *data, size_t n) {
    size_t cap;
    char *j;
    int o;
    if (n > FLIM_CLOUD_MAX || (n && !data)) goto failed;
    cap = 160 + (n + 2) / 3 * 4 + 1;
    j = (char *)malloc(cap);
    if (!j) goto failed;
    o = unit == U_CH ? sprintf_s(j, cap, "\"unit\":\"ch\",\"ch\":%d,\"data\":\"", a)
                         : sprintf_s(j, cap, "\"unit\":\"fx\",\"trk\":%d,\"slot\":%d,\"data\":\"", a, b);
    b64enc(data, (int)n, j + o);
    strcat_s(j, cap, "\"");
    { Unit *u = unit_ptr(unit, a, b);
      if (u && u->unavailable && u->presetFl[0]) { size_t used = strlen(j); sprintf_s(j + used, cap - used, ",\"preset_fl\":\"%s\"", u->presetFl); } }
    return j;
failed:
    sharing_fail("Shared plugin: session stopped", "The plugin state exceeds its size limit or could not fit in memory. No incomplete state was sent.");
    return NULL;
}

// key: the plugin lock the op is sent under (NULL = none); the server drops it if a peer holds it.
static void send_unit(const char *kind, int unit, int a, int b, const unsigned char *data, size_t n, const char *key) {
    char *f = unit_json_fields(unit, a, b, data, n);
    size_t cap;
    char *m;
    if (!f) return;
    cap = strlen(f) + 128;
    m = (char *)malloc(cap);
    if (!m) { free(f); sharing_fail("Shared plugin: session stopped", "There is not enough memory to send the shared plugin state."); return; }
    if (key) sprintf_s(m, cap, "{\"t\":\"op\",\"op\":{\"kind\":\"%s\",\"key\":\"%s\",%s}}", kind, key, f);
    else sprintf_s(m, cap, "{\"t\":\"op\",\"op\":{\"kind\":\"%s\",%s}}", kind, f);
    ws_send_samples(m, data, n);         // lists (and uploads) the samples the state uses
    free(f);
    logmsg("PLUG sent %s unit=%s %d/%d (%zu bytes)", kind, unit == U_CH ? "ch" : "fx", a, b, n);
}

static void do_snap(const QItem *it) {
    Unit *u = unit_ptr(it->unit, it->a, it->b);
    size_t n = 0;
    if (!u || u->unavailable || unit_applying(u, GetTickCount())) return;
    unsigned char *d = unit_save(it->unit, it->a, it->b, &n);
    if (!d) return;
    uint64_t h = state_hash(d, n);
    DWORD now = GetTickCount();
    // Provenance: a state goes out only if the local user did something since this
    // unit's baseline. Some plugins (Serum) never save byte-identical state twice;
    // without this gate that drift ping-pongs full reloads between the peers.
    int userSince = g_lastInput && (LONG)(g_lastInput - u->baseAt) > 0;
    int send = 0;
    char key[32];
    switch (it->mode) {
    case SNAP_IF_DIFF:
        if (u->hash && h != u->hash) {
            if (userSince) send = 1;
            else logmsg("PLUG drift absorbed unit=%s %d/%d (no local input)", it->unit == U_CH ? "ch" : "fx", it->a, it->b);
        }
        break;
    case SNAP_FORCE:   send = 1; break;   // identity changed: always
    case SNAP_ADD:     send_unit("chan.add", it->unit, it->a, it->b, d, n, NULL); break;
    default: break;
    }
    if (send) {
        if (!compat_plugin_send()) {
            free(d);
            plug_revert_state(it->unit, it->a, it->b);
            fl_hint("This room's oldest FL host must change plugin presets. The agreed preset is being restored; notes and controls remain shared.");
            return;
        }
        if (!plug_lock_send(it->unit, it->a, it->b, key, sizeof(key))) {
            // someone else is editing this plugin: put back the state everyone agreed on
            free(d);
            plug_revert_state(it->unit, it->a, it->b);
            return;
        }
        send_unit("plug.state", it->unit, it->a, it->b, d, n, key);
    }
    plug_agreed_set(it->unit, it->a, it->b, d, n);
    u->hash = h;
    u->baseAt = now;
    free(d);
}

static void do_load(const QItem *it) {
    Unit *u = unit_ptr(it->unit, it->a, it->b);
    void *obj = unit_obj(it->unit, it->a, it->b);
    if (!u || !obj || !it->path) {
        sharing_fail("Shared plugin: session stopped", "The shared plugin target no longer exists. Reconnect and resync before continuing to share.");
        return;
    }
    size_t n = 0;
    unsigned char *in = read_file(it->path, &n);
    if (!in || !n) {
        free(in);
        sharing_fail("Shared plugin: session stopped", "The received preset could not be read completely. Your previous agreed plugin state was kept.");
        return;
    }
    uint64_t hin = state_hash(in, n);
    unsigned char *local = NULL;
    size_t localn = 0;
    char reason[320] = "";
    uint64_t retryStamp = 0;
    if (u->unavailable && u->hash == hin && it->mode != 2) {
        if (it->mode == 3) {
            strcpy_s(u->presetFl, sizeof(u->presetFl), it->presetFl);
            u->retryStamp = 0;
            InterlockedExchange(&u->unavailable, 2);
            plugins_changed();
        }
        free(in); return;
    }
    if (it->mode == 3) { strcpy_s(reason, sizeof(reason), "Newer FL preset retained without passing it to this older FL loader"); goto unavailable; }
    int prepared = plugin_prepare(in, n, it->unit, &local, &localn, reason, sizeof(reason));
    retryStamp = plugin_retry_stamp(in, n, it->unit);
    if (prepared < 0) {
        free(in);
        sharing_fail("Shared plugin: session stopped", "There is not enough memory to adapt the shared plugin path.");
        return;
    }
    if (!prepared) goto unavailable;
    if (!u->unavailable && it->mode == 1) {       // join: skip units that are already identical
        size_t m = 0;
        unsigned char *own = unit_save(it->unit, it->a, it->b, &m);
        uint64_t hown = own ? state_hash(own, m) : 0;
        free(own);
        if (g_compatFault) { free(local); free(in); return; }
        if (hown && hown == hin) {
            plug_agreed_set(it->unit, it->a, it->b, in, n);
            free(local); free(in); u->hash = hown; return;
        }
    }
    char *adapted = NULL;
    if (local) {
        FILE *f = NULL;
        int ok = 0;
        adapted = tmp_path("vp");
        if (adapted && !fopen_s(&f, adapted, "wb") && f) {
            ok = fwrite(local, 1, localn, f) == localn;
            if (fclose(f)) ok = 0;
        }
        free(local); local = NULL;
        if (!ok) {
            if (adapted) { DeleteFileA(adapted); free(adapted); }
            free(in);
            sharing_fail("Shared plugin: session stopped", "The local plugin preset could not be written completely. Check the temporary folder and free disk space.");
            return;
        }
    }
    wchar_t *w = dstr_new(adapted ? adapted : it->path);
    if (!w) {
        if (adapted) { DeleteFileA(adapted); free(adapted); }
        free(in);
        sharing_fail("Shared plugin: session stopped", "There is not enough memory to load the shared preset. Your previous agreed plugin state was kept.");
        return;
    }
    InterlockedIncrement(&u->applyGen);
    int r = -1, fault = 0;
    __try { r = g_loadPreset(w, unit_mask(it->unit), obj, 0); }
    __except (EXCEPTION_EXECUTE_HANDLER) { fault = 1; logmsg("LOAD faulted unit=%d %d/%d", it->unit, it->a, it->b); }
    dstr_free(w);
    if (adapted) { DeleteFileA(adapted); free(adapted); }
    if (fault) {
        free(in);
        InterlockedIncrement(&u->applyGen);
        sharing_fail("Shared plugin: session stopped", "A native plugin load faulted. Sharing stopped because FL's memory state may be unsafe. The previous agreed state was kept.");
        return;
    }
    if (r != 0 || (reason[0] && !plugin_inst(obj))) {
        InterlockedIncrement(&u->applyGen);
        strcpy_s(reason, sizeof(reason), "FL Studio rejected this preset or did not create the requested plugin");
        goto unavailable;
    }
    if (!plug_agreed_set(it->unit, it->a, it->b, in, n)) { free(in); InterlockedIncrement(&u->applyGen); return; }
    free(in);
    if (InterlockedExchange(&u->unavailable, 0)) plugins_changed();
    u->identAt = 0; u->lastAct = 0; u->burst = 0;
    u->inst = plugin_inst(obj);                 // ours: the structure scan must not report it back
    // The load moved this unit's params; take them as the new truth right away
    // (instead of ignoring local edits for seconds), plus a short window for
    // plugins that update params asynchronously after a state load.
    {
        int i, k = 0, un, ua, ub;
        for (i = 0; i < g_nslot; i++) {
            Slot *s = &g_slots[i];
            if (!unit_of_id(s->id, &un, &ua, &ub) || un != it->unit || ua != it->a || ub != it->b) continue;
            EnterCriticalSection(&g_slotLock);
            s->last = read_value(s->id);
            s->hasUndo = 0;
            InterlockedIncrement(&s->gen);
            LeaveCriticalSection(&g_slotLock);
            k++;
        }
        DWORD now = GetTickCount();
        u->suppressUntil = now + SUPPRESS_MS;
        u->absorbUntil = now + ABSORB_MS;
        u->baseAt = now;
        u->baselineAt = now + REBASE_MS;
        (void)k;
    }
    InterlockedIncrement(&u->applyGen);
    logmsg("PLUG applied unit=%s %d/%d ret=%d", it->unit == U_CH ? "ch" : "fx", it->a, it->b, r);
    return;
unavailable:
    free(local);
    if (!plug_agreed_set(it->unit, it->a, it->b, in, n)) { free(in); return; }
    free(in);
    u->hash = hin;
    u->identAt = u->addAt = u->lastAct = u->baselineAt = 0; u->burst = 0;
    u->inst = plugin_inst(obj);
    u->retryStamp = retryStamp;
    strcpy_s(u->presetFl, sizeof(u->presetFl), it->presetFl);
    InterlockedExchange(&u->unavailable, it->mode == 3 ? 2 : 1);
    plugins_changed();
    logmsg("PLUGIN unavailable unit=%s %d/%d: %s; remote state retained, room stays connected", it->unit == U_CH ? "ch" : "fx", it->a, it->b, reason);
    fl_hint("Plugin unavailable here. Notes and shared controls continue. Matching scanned plugins recover automatically.");
}

static void units_shift_after_delete(int idx, int n) {
    int i;
    pending_channels(NULL, n, idx);
    plug_agreed_channels(NULL, n, idx);
    for (i = idx; i + 1 < n && i + 1 < MAX_CH; i++) g_chU[i] = g_chU[i + 1];
    if (n - 1 >= 0 && n - 1 < MAX_CH) memset(&g_chU[n - 1], 0, sizeof(Unit));
    for (i = idx; i < MAX_CH; i++) {
        g_chanPlugN[i] = 0;          // param ranges re-probed by rescan
        g_chU[i].hash = 0;           // saved state is index-dependent: re-baseline, don't send
    }
    plugins_changed();
    InterlockedIncrement(&g_structGen);
}

static void known_from_list(void) {
    void **items; int n = chan_list(&items), i;
    for (i = 0; i < n; i++) g_chKnown[i] = items[i];
    g_nChKnown = n;
}

static void do_addch(const QItem *it) {
    void **items, *before[MAX_CH]; int i, n = chan_list(&items), fault = 0;
    if (it->unit != U_CH || it->a < 0 || n != it->a || n >= MAX_CH || (n && !items)) {
        logmsg("chan.add: expected index %d but have %d channels", it->a, n);
        sharing_fail("Shared channel: session stopped", "The channel lists no longer match. Reconnect and resync before continuing to share.");
        return;
    }
    for (i = 0; i < n; i++) before[i] = items[i];
    void *obj = NULL;
    __try { obj = g_addChannel(-1, 0, 1); } __except (EXCEPTION_EXECUTE_HANDLER) { fault = 1; }
    if (fault || !obj || chan_list(&items) != n + 1 || !items || items[n] != obj) {
        sharing_fail("Shared channel: session stopped", "FL Studio could not add the shared channel. Reconnect and resync before continuing to share.");
        return;
    }
    for (i = 0; i < n; i++) if (items[i] != before[i]) {
        sharing_fail("Shared channel: session stopped", "FL Studio changed another channel while adding this channel. Reconnect and resync before continuing to share."); return;
    }
    known_from_list();
    memset(&g_chU[it->a], 0, sizeof(Unit));
    g_chU[it->a].absorbUntil = GetTickCount() + SUPPRESS_MS + SETTLE_IDENT_MS;
    logmsg("CHAN added index %d (remote)", it->a);
    // Initialize before later parameter, delete or reorder tasks can change this index.
    do_load(it);
}

static void do_delch(const QItem *it) {
    void **items, *before[MAX_CH]; int i, n = chan_list(&items), fault = 0;
    if (it->a < 0 || it->a >= n || !items) {
        sharing_fail("Shared channel: session stopped", "The channel selected for deletion no longer exists. Reconnect and resync before continuing to share."); return;
    }
    for (i = 0; i < n; i++) before[i] = items[i];
    __try { g_delChannel((unsigned)it->a, 0, DELCHAN_FLAGS); } __except (EXCEPTION_EXECUTE_HANDLER) { fault = 1; }
    if (fault || chan_list(&items) != n - 1 || (n > 1 && !items)) {
        sharing_fail("Shared channel: session stopped", "FL Studio did not confirm the channel deletion. Channel bookkeeping was kept."); return;
    }
    for (i = 0; i < n - 1; i++) if (items[i] != before[i < it->a ? i : i + 1]) {
        sharing_fail("Shared channel: session stopped", "FL Studio changed another channel during deletion. Reconnect and resync before continuing to share."); return;
    }
    units_shift_after_delete(it->a, n);
    known_from_list();
    notes_rebaseline(1);
    logmsg("CHAN deleted index %d (remote)", it->a);
}

// Channels changed places: carry each channel's unit bookkeeping (plugin identity etc.)
// along to its new index. Saved channel state embeds the index, so moved channels
// re-baseline their hash silently; their param ranges are re-probed and every param
// is re-read without being sent (g_structGen) -- the values moved with the channels.
static void units_permute(const int *from, int n) {
    static Unit old[MAX_CH];
    int i;
    memcpy(old, g_chU, sizeof(Unit) * (size_t)n);
    pending_channels(from, n, -1);
    plug_agreed_channels(from, n, -1);
    for (i = 0; i < n; i++) {
        g_chU[i] = old[from[i]];
        if (from[i] != i) {
            g_chU[i].hash = 0; g_chU[i].identAt = 0; g_chU[i].lastAct = 0; g_chU[i].burst = 0;
            g_chanPlugN[i] = 0;
        }
    }
    plugins_changed();
    InterlockedIncrement(&g_structGen);
}

// Remove the effect from a mixer slot the way FL's slot menu "Delete" does: load the
// "(delete) effect" preset into it. Main thread.
static void do_fxclear(const QItem *it) {
    Unit *u = unit_ptr(U_FX, it->a, it->b);
    void *obj = fx_obj(it->a, it->b);
    if (!u || !obj) {
        sharing_fail("Shared effect: session stopped", "The shared mixer slot no longer exists. Reconnect and resync before continuing to share.");
        return;
    }
    if (!plugin_inst(obj)) {
        if (u->unavailable) {
            memset(u, 0, offsetof(Unit, applyGen));
            u->absorbUntil = GetTickCount() + ABSORB_MS;
            plug_agreed_set(U_FX, it->a, it->b, NULL, 0); plugins_changed();
            logmsg("PLUGIN unavailable state discarded for empty fx %d/%d (remote clear)", it->a, it->b);
        }
        return;
    }
    wchar_t *w = dstr_new(g_fxDeletePreset);
    if (!w) { sharing_fail("Shared effect: session stopped", "There is not enough memory to clear the shared effect. Your previous agreed plugin state was kept."); return; }
    int r = -1;
    InterlockedIncrement(&u->applyGen);
    __try { r = g_loadPreset(w, MASK_FX, obj, 0); }
    __except (EXCEPTION_EXECUTE_HANDLER) { logmsg("FX clear faulted %d/%d", it->a, it->b); }
    dstr_free(w);
    if (r != 0 || plugin_inst(obj)) {
        InterlockedIncrement(&u->applyGen);
        sharing_fail("Shared effect: session stopped", "FL Studio could not remove the shared effect. Check the plugin error before reconnecting; the previous agreed state was kept.");
        return;
    }
    memset(u, 0, offsetof(Unit, applyGen));
    plug_agreed_set(U_FX, it->a, it->b, NULL, 0);
    u->absorbUntil = GetTickCount() + ABSORB_MS;
    InterlockedIncrement(&u->applyGen);
    plugins_changed();
    logmsg("PLUG cleared fx %d/%d (remote) ret=%d", it->a, it->b, r);
}

// Join: slots the leader has empty (absent from plug.full) must be empty here too.
static void do_fxsync(const QItem *it) {
    const unsigned char *keep = (const unsigned char *)it->order;
    int t, s, n = 0, nm = mix_count();
    for (t = 0; t < nm; t++)
        for (s = 0; s < MAX_FX_SLOTS; s++) {
            if (keep[t * MAX_FX_SLOTS + s] || (!g_fxU[t][s].unavailable && !plugin_inst(fx_obj(t, s)))) continue;
            enqueue_unit(T_FXCLEAR, U_FX, t, s, 0, NULL);
            n++;
        }
    if (n) logmsg("PLUG join: clearing %d effect slots the leader has empty", n);
}

static int index_of(void **list, int n, void *o) {
    int i;
    for (i = 0; i < n; i++) if (list[i] == o) return i;
    return -1;
}

// Remote reorder: rebuild the peer's order with FL's own "move selected up", one
// channel at a time (select only it, move, repeat), then restore our selection.
// Works on the rack's filter-group list like FL does; channels outside the group
// must stay where they are.
static void do_order(const QItem *it) {
    int n, i, j, steps = 0, selected = 0;
    if (!it->order || (n = it->order[0]) < 0 || n > MAX_CH) {
        sharing_fail("Channel order: session stopped", "The shared channel order is invalid. Your channel selection was kept."); return;
    }
    const int *from = it->order + 1;
    void **items, **filt;
    static void *M[MAX_CH], *T[MAX_CH], *D[MAX_CH];
    static unsigned char sel[MAX_CH];
    int nm = chan_list(&items);
    if (!items || nm != n || g_nChKnown != n) { logmsg("chan.order: have %d channels (known %d), peer %d; skipped", nm, g_nChKnown, n); return; }
    {
        unsigned char seen[MAX_CH] = { 0 };
        for (i = 0; i < n; i++) {
            if (from[i] < 0 || from[i] >= n || seen[from[i]]) { logmsg("chan.order: not a permutation; skipped"); return; }
            seen[from[i]] = 1;
        }
    }
    for (i = 0; i < n; i++) { M[i] = items[i]; T[i] = items[from[i]]; }
    for (i = 0; i < n && from[i] == i; i++) {}
    if (i == n) return;
    int nf = chan_list_filtered(&filt), nd = 0;
    if (!filt) return;
    for (i = 0; i < n; i++) {
        int inF = index_of(filt, nf, M[i]) >= 0;
        if (!inF && T[i] != M[i]) { logmsg("chan.order: channel %d is outside the rack's filter group; skipped", i); return; }
        if (index_of(filt, nf, T[i]) >= 0) D[nd++] = T[i];
    }
    if (nd != nf) { logmsg("chan.order: filter list mismatch (%d vs %d); skipped", nd, nf); return; }
    void *obj = NULL; int arg = -1;
    __try {
        obj = **(void ***)(g_flBase + (MOVEOBJ_VA - IMG_BASE));
        arg = **(int **)(g_flBase + (MOVEARG_VA - IMG_BASE));
        for (i = 0; i < n; i++) sel[i] = *((unsigned char *)M[i] + CH_SELECTED);
        selected = 1;
        for (i = 0; i < nd; i++) {
            nf = chan_list_filtered(&filt);
            j = index_of(filt, nf, D[i]);
            while (j > i) {
                int k, j2;
                for (k = 0; k < nf; k++) *((unsigned char *)filt[k] + CH_SELECTED) = (unsigned char)(k == j);
                g_moveChans(obj, MOVE_UP, arg, MOVE_FLAGS);
                steps++;
                nf = chan_list_filtered(&filt);
                j2 = index_of(filt, nf, D[i]);
                if (j2 != j - 1) { logmsg("chan.order: move did not take (%d -> %d); stopping", j, j2); i = nd; break; }
                j = j2;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { logmsg("chan.order faulted after %d moves", steps); }
    if (selected) for (i = 0; i < n; i++) {
        __try { *((unsigned char *)M[i] + CH_SELECTED) = sel[i]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { logmsg("chan.order selection restore failed at %d", i); }
    }
    nm = chan_list(&items);
    int ok = nm == n;
    for (i = 0; ok && i < n; i++) ok = items[i] == T[i];
    if (ok) units_permute(from, n);
    else {
        // out of step with the peer's order: keep our bookkeeping consistent with what FL has
        for (i = 0; i < nm; i++) { g_chU[i].hash = 0; g_chU[i].inst = plugin_inst(items[i]); g_chanPlugN[i] = 0; }
        plug_agreed_reset(1, 0);
        InterlockedIncrement(&g_structGen);
        sharing_fail("Channel order: session stopped", "FL Studio could not reproduce the shared channel order. Reconnect and resync before continuing to share.");
    }
    known_from_list();
    notes_rebaseline(1);
    logmsg("CHAN reordered (remote): %d moves, %s", steps, ok ? "order matches" : "ORDER MISMATCH");
}

// Compare FL's channel list and plugin instances with what we knew.
static void do_struct(void) {
    void **items; int n = chan_list(&items), i, t, s;
    DWORD now = GetTickCount();
    if (!items) return;
    if (g_nChKnown < 0) {
        known_from_list();
        for (i = 0; i < n; i++) g_chU[i].inst = plugin_inst(items[i]);
        for (t = 0; t < mix_count(); t++)
            for (s = 0; s < MAX_FX_SLOTS; s++) g_fxU[t][s].inst = plugin_inst(fx_obj(t, s));
        return;
    }
    if (g_nChKnown > 0) {
        // Every known channel gone (project load/new/close): not a series of deletes.
        int k, j, common = 0;
        for (k = 0; k < g_nChKnown && !common; k++)
            for (j = 0; j < n; j++) if (items[j] == g_chKnown[k]) { common = 1; break; }
        if (!common) { proj_begin("channel list replaced"); return; }
    }
    if (closing_now()) return;
    int prefixSame = 1;
    for (i = 0; i < n && i < g_nChKnown; i++) if (items[i] != g_chKnown[i]) { prefixSame = 0; break; }
    if (n > g_nChKnown && prefixSame) {
        for (i = g_nChKnown; i < n; i++) {
            memset(&g_chU[i], 0, sizeof(Unit));
            g_chU[i].addAt = now;
            logmsg("CHAN appended locally: index %d", i);
        }
        known_from_list();
    } else if (n != g_nChKnown || !prefixSame) {
        // find deleted channels (known objects no longer in the list), highest index first
        int k, j, deleted = 0;
        for (k = g_nChKnown - 1; k >= 0; k--) {
            for (j = 0; j < n && items[j] != g_chKnown[k]; j++) {}
            if (j == n) {
                char m[96];
                sprintf_s(m, sizeof(m), "{\"t\":\"op\",\"op\":{\"kind\":\"chan.del\",\"ch\":%d}}", k);
                ws_send(m);
                logmsg("CHAN deleted locally: index %d (sent)", k);
                units_shift_after_delete(k, g_nChKnown - deleted);
                deleted++;
            }
        }
        if (!deleted && n == g_nChKnown) {
            // Reorder (move up/down, sort): send the permutation; the peer replays it
            // with FL's own move, so channels keep their state and params as they travel.
            int from[MAX_CH], moved = 0, ok = 1;
            char m[64 + MAX_CH * 5];
            int len = sprintf_s(m, sizeof(m), "{\"t\":\"op\",\"op\":{\"kind\":\"chan.order\",\"n\":%d,\"from\":[", n);
            for (i = 0; i < n; i++) {
                for (j = 0; j < n && g_chKnown[j] != items[i]; j++) {}
                if (j == n) { ok = 0; break; }
                from[i] = j;
                if (j != i) moved++;
                len += sprintf_s(m + len, sizeof(m) - len, "%s%d", i ? "," : "", j);
            }
            if (ok) {
                strcat_s(m, sizeof(m), "]}}");
                ws_send(m);
                units_permute(from, n);
                logmsg("CHAN list reordered locally: %d channels moved (sent chan.order)", moved);
            } else logmsg("CHAN list reordered with unknown channels; not synced");
            known_from_list();
        } else if (!deleted) logmsg("CHAN list changed in an unsupported way (count %d -> %d)", g_nChKnown, n);
        known_from_list();
        notes_rebaseline(1);          // the peer replays the same structural change
        InterlockedIncrement(&g_structGen);
    }
    // plugin identity (add/replace) per channel and mixer slot
    for (i = 0; i < n; i++) {
        void *inst = plugin_inst(items[i]);
        Unit *u = &g_chU[i];
        if (u->unavailable) { u->inst = inst; continue; }
        if (inst != u->inst) {
            u->inst = inst;
            if (now < u->absorbUntil || u->addAt) continue;
            if (inst) { u->identAt = now; logmsg("PLUG identity changed: ch %d", i); }
        }
    }
    int nm = mix_count(), gone = 0;
    for (t = 0; t < nm; t++)
        for (s = 0; s < MAX_FX_SLOTS; s++)
            if (!g_fxU[t][s].unavailable && g_fxU[t][s].inst && !plugin_inst(fx_obj(t, s)) && now >= g_fxU[t][s].absorbUntil) gone++;
    if (gone >= PROJ_FX_MASS) { proj_begin("many effects removed at once"); return; }
    for (t = 0; t < nm; t++)
        for (s = 0; s < MAX_FX_SLOTS; s++) {
            Unit *u = &g_fxU[t][s];
            void *inst = plugin_inst(fx_obj(t, s));
            if (u->unavailable) { u->inst = inst; continue; }
            if (inst == u->inst) continue;
            void *was = u->inst;
            u->inst = inst;
            if (now < u->absorbUntil) continue;
            if (inst) { u->identAt = now; logmsg("PLUG identity changed: fx %d/%d", t, s); }
            else if (was) {
                char m[112];
                sprintf_s(m, sizeof(m), "{\"t\":\"op\",\"op\":{\"kind\":\"fx.clear\",\"trk\":%d,\"slot\":%d}}", t, s);
                ws_send(m);
                u->identAt = 0; u->lastAct = 0; u->hash = 0;
                plug_agreed_set(U_FX, t, s, NULL, 0);
                logmsg("PLUG removed from fx %d/%d (sent fx.clear)", t, s);
            }
        }
}

// Leader: every unit's state, then the param values (join / project load).
static void do_full(void) {
    void **items; int n = chan_list(&items), i, t, s, cnt = 0;
    size_t cap = 256, len;
    char *m = (char *)malloc(cap);
    if (!m) goto failed;
    len = sprintf_s(m, cap, "{\"t\":\"op\",\"op\":{\"kind\":\"plug.full\",\"nch\":%d,\"items\":[", n);
    for (i = 0; i < n + mix_count() * MAX_FX_SLOTS; i++) {
        int unit = i < n ? U_CH : U_FX;
        int a = i < n ? i : (i - n) / MAX_FX_SLOTS, b = i < n ? 0 : (i - n) % MAX_FX_SLOTS;
        size_t dn = 0;
        Unit *u = unit_ptr(unit, a, b);
        unsigned char *d = u && u->unavailable ? plug_agreed_copy(unit, a, b, &dn) : unit_save(unit, a, b, &dn);
        if (g_compatFault) { free(d); goto failed; }
        if (!d) { if (unit == U_CH || (u && u->unavailable)) goto failed; continue; }
        if (u) u->hash = state_hash(d, dn);
        char *f = unit_json_fields(unit, a, b, d, dn);
        free(d);
        if (!f) goto failed;
        size_t fl = strlen(f);
        if (len > FLIM_CLOUD_MAX - 8 || fl > FLIM_CLOUD_MAX - 8 - len) { free(f); goto failed; }
        if (len + fl + 8 > cap) {
            size_t need = len + fl + 8;
            char *next;
            cap = need > FLIM_CLOUD_MAX / 2 ? FLIM_CLOUD_MAX : need * 2;
            next = (char *)realloc(m, cap);
            if (!next) { free(f); goto failed; }
            m = next;
        }
        len += sprintf_s(m + len, cap - len, "%s{%s}", cnt ? "," : "", f);
        free(f);
        cnt++;
    }
    strcat_s(m, cap, "]}}");
    ws_send(m);
    free(m);
    logmsg("PLUG full state sent: %d channels, %d units", n, cnt);
    (void)t; (void)s;
    send_notes_full();
    send_full_state();
    return;
failed:
    free(m);
    sharing_fail("Shared plugins: session stopped", "The complete plugin snapshot could not be prepared within its size and memory limits. No incomplete snapshot was sent.");
}

// ---------------- notes ----------------
// Unit = one pattern (all channels' notes in it). Detection hashes every pattern's
// note array from the poll thread (SEH-guarded, no lock: a torn read just shows up as
// a change that settles); snapshots and applies run on the main thread under FL's own
// note lock, so the audio thread never sees a half-replaced pattern.
static uint64_t g_patHash[MAX_PAT];       // last state sent or applied (0 = no notes)
static uint64_t g_patSeen[MAX_PAT];       // last state the scanner saw
static DWORD    g_patChangedAt[MAX_PAT];  // when g_patSeen last moved (0 = settled/handled)
static DWORD    g_patDirtyAt[MAX_PAT];    // first unsent observation, bounded during recording
static volatile DWORD g_patSuppress[MAX_PAT];
static volatile LONG g_notesReady = 0;    // baseline taken
static volatile LONG g_notesCrdt = 0;     // negotiated by every participant through the relay
static FncState g_noteSets[MAX_PAT];
static unsigned g_noteSetCount;
static CRITICAL_SECTION g_ulockLock;
static void notes_crdt_rebaseline(void);
static int sha_hex(const void *p, size_t n, char hex[65]);

#define NOTES_SCAN_MS   100
#define NOTES_SETTLE_MS 100
#define NOTES_STREAM_MS 200     // keep recorded MIDI moving while notes are still being added

static int notes_suppressed(volatile DWORD *until, DWORD now) {
    LONG deadline = InterlockedCompareExchange((volatile LONG *)until, 0, 0);
    if (!deadline) return 0;
    if ((LONG)(now - (DWORD)deadline) < 0) return 1;
    InterlockedCompareExchange((volatile LONG *)until, 0, deadline);
    return 0;
}

// Hash of note records with the selection bit masked out: selecting is not an edit.
static uint64_t notes_fnv(const unsigned char *p, unsigned n) {
    uint64_t sum = 0, mixed = 0;
    unsigned i, j;
    for (i = 0; i < n; i++) {
        uint64_t h = 1469598103934665603ull;
        for (j = 0; j < NOTE_SIZE; j++) {
            unsigned char v = p[(size_t)i * NOTE_SIZE + j];
            if (j == NOTE_SEL_OFS) v &= (unsigned char)~NOTE_SEL_BIT;
            h = (h ^ v) * 1099511628211ull;
        }
        sum += h; mixed += h * (h ^ 0x9e3779b97f4a7c15ull);
    }
    sum ^= (mixed << 23) | (mixed >> 41); sum ^= (uint64_t)n * 0x9e3779b97f4a7c15ull;
    return sum ? sum : 1;
}

static void notes_clear_sel(unsigned char *d, unsigned n) {
    unsigned i;
    for (i = 0; i < n; i++) d[(size_t)i * NOTE_SIZE + NOTE_SEL_OFS] &= (unsigned char)~NOTE_SEL_BIT;
}

static char *pat_notes_arr(int p) {
    char *tbl = *(char **)(g_flBase + (PATARR_VA - IMG_BASE));
    return *(char **)(tbl + (size_t)p * PAT_STRIDE + PAT_NOTES);
}

static CRITICAL_SECTION *note_lock(void) { return *(CRITICAL_SECTION **)(g_flBase + (NOTELOCK_VA - IMG_BASE)); }

static uint64_t notes_hash(int p) {
    uint64_t h = 0;
    EnterCriticalSection(note_lock());
    __try {
        char *a = pat_notes_arr(p);
        unsigned n = a ? *(unsigned *)(a + NOTES_COUNT) : 0;
        h = n > 1000000 ? 1 : n ? notes_fnv(*(unsigned char **)(a + NOTES_DATA), n) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) { h = 1; }
    LeaveCriticalSection(note_lock());
    return h;
}

// Copy of pattern p's note records (main thread, under FL's note lock). *n = count.
static unsigned char *notes_copy(int p, unsigned *n) {
    unsigned char *buf = NULL;
    *n = 0;
    EnterCriticalSection(note_lock());
    __try {
        char *a = pat_notes_arr(p);
        unsigned c = a ? *(unsigned *)(a + NOTES_COUNT) : 0;
        if (c > 1000000) { *n = UINT_MAX; }
        else if (c) {
            buf = (unsigned char *)malloc((size_t)c * NOTE_SIZE);
            if (!buf) *n = UINT_MAX;
            else {
                memcpy(buf, *(unsigned char **)(a + NOTES_DATA), (size_t)c * NOTE_SIZE);
                *n = c;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { free(buf); buf = NULL; *n = UINT_MAX; }
    LeaveCriticalSection(note_lock());
    return buf;
}

// Take the current note state of every pattern as already known (no sends).
static void notes_rebaseline(int channels_only) {
    int p;
    for (p = 1; p < MAX_PAT; p++) { g_patSeen[p] = g_patHash[p] = notes_hash(p); g_patChangedAt[p] = g_patDirtyAt[p] = 0; }
    if (g_notesCrdt) notes_crdt_rebaseline();
    clips_rebaseline();          // audio clips reference channels: same structural events
    meta_rebaseline(channels_only); // channel changes must preserve unrelated pending metadata
    units_capture_all();         // and it is the state a lock conflict reverts to
}

static void redraw_editors(void);

typedef struct { unsigned char rec[NOTE_SIZE]; unsigned index, selected; } NoteApplyRef;
static int notes_apply_cmp(const void *a, const void *b) {
    const NoteApplyRef *x = (const NoteApplyRef *)a, *y = (const NoteApplyRef *)b;
    int order = memcmp(x->rec, y->rec, NOTE_SIZE);
    if (order) return order;
    if (x->selected != y->selected) return x->selected ? -1 : 1;
    return x->index < y->index ? -1 : x->index > y->index;
}

// Match identical records before mutating FL. Keep selected duplicates first so
// reducing a stack of identical notes does not unnecessarily discard the selection.
static int notes_apply_plan(const unsigned char *old, unsigned c, const unsigned char *in, unsigned n,
                            unsigned char *keep, unsigned char *insert) {
    NoteApplyRef *before = c ? (NoteApplyRef *)malloc((size_t)c * sizeof(*before)) : NULL;
    NoteApplyRef *after = n ? (NoteApplyRef *)malloc((size_t)n * sizeof(*after)) : NULL;
    unsigned i, a = 0, b = 0;
    if ((c && !before) || (n && !after)) { free(before); free(after); return 0; }
    for (i = 0; i < c; i++) {
        memcpy(before[i].rec, old + (size_t)i * NOTE_SIZE, NOTE_SIZE);
        before[i].selected = !!(before[i].rec[NOTE_SEL_OFS] & NOTE_SEL_BIT);
        before[i].rec[NOTE_SEL_OFS] &= (unsigned char)~NOTE_SEL_BIT; before[i].index = i;
    }
    for (i = 0; i < n; i++) { memcpy(after[i].rec, in + (size_t)i * NOTE_SIZE, NOTE_SIZE); after[i].index = i; after[i].selected = 0; }
    if (c) qsort(before, c, sizeof(*before), notes_apply_cmp);
    if (n) qsort(after, n, sizeof(*after), notes_apply_cmp);
    if (n) memset(insert, 1, n);
    while (a < c && b < n) {
        int order = memcmp(before[a].rec, after[b].rec, NOTE_SIZE);
        if (!order) { keep[before[a++].index] = 1; insert[after[b++].index] = 0; }
        else if (order < 0) a++; else b++;
    }
    free(before); free(after); return 1;
}

// Main thread under FL's note lock. Preserve unchanged records in place; a small
// incoming delta must not delete and re-add thousands of unrelated recorded notes.
static void notes_apply(int p, const unsigned char *recs, unsigned n) {
    unsigned i;
    int k, applied = 0, changed = 0;
    unsigned char *in = n ? (unsigned char *)malloc((size_t)n * NOTE_SIZE) : NULL;
    unsigned char *keep = NULL, *insert = n ? (unsigned char *)malloc(n) : NULL;
    if (n > 1000000 || (n && (!in || !insert || !recs))) {
        free(in); free(insert);
        sharing_fail("Note sync: session stopped", "There is not enough memory to apply the remote notes. Your local notes were kept.");
        return;
    }
    if (in) { memcpy(in, recs, (size_t)n * NOTE_SIZE); notes_clear_sel(in, n); }
    EnterCriticalSection(note_lock());
    __try {
        char *a = (char *)g_noteArr(p, 1);
        if (a) {
            noteadd_t add = (noteadd_t)(*(void ***)a)[NOTEADD_VSLOT];
            unsigned c = *(unsigned *)(a + NOTES_COUNT);
            if (c > 1000000) __leave;
            keep = c ? (unsigned char *)calloc(c, 1) : NULL;
            if (c && !keep) __leave;
            if (!notes_apply_plan(c ? *(unsigned char **)(a + NOTES_DATA) : NULL, c, in, n, keep, insert)) __leave;
            for (k = (int)c - 1; k >= 0; k--) if (!keep[k]) { g_noteDel(a, k, 0); changed = 1; }
            for (i = 0; i < n; i++) if (insert[i]) { add(a, in + (size_t)i * NOTE_SIZE); changed = 1; }
            applied = *(unsigned *)(a + NOTES_COUNT) == n;
            if (applied && n) {
                /* Reuse the plan to verify the exact multiset, including duplicate notes. */
                unsigned char *actual = *(unsigned char **)(a + NOTES_DATA);
                unsigned char *verified = (unsigned char *)calloc(n, 1);
                applied = verified && notes_apply_plan(actual, n, in, n, verified, insert);
                if (applied) for (i = 0; i < n; i++) if (insert[i]) { applied = 0; break; }
                free(verified);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { logmsg("NOTES apply faulted pat %d", p); }
    LeaveCriticalSection(note_lock());
    free(keep); free(insert);
    if (!applied) {
        free(in);
        sharing_fail("Note sync: session stopped", "FL could not apply the remote notes. Reconnect and resync before continuing to share.");
        return;
    }
    unit_agreed(1, p, recs, n);
    free(in);
    if (changed) {
        void **items; int nc = chan_list(&items);
        __try {
            for (k = 0; k < nc; k++) {
                void *grid = *(void **)((char *)items[k] + CH_GRID);
                if (grid) g_gridRefresh(grid);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { logmsg("NOTES grid refresh faulted"); }
    }
    if (changed) redraw_editors();
    g_patSeen[p] = g_patHash[p] = notes_hash(p);
    g_patChangedAt[p] = g_patDirtyAt[p] = 0;
    g_patSuppress[p] = GetTickCount() + NOTES_SETTLE_MS;
}

static char *notes_json_item(int p, const unsigned char *d, unsigned n) {
    size_t cap = 48 + ((size_t)n * NOTE_SIZE + 2) / 3 * 4 + 1;
    char *j = (char *)malloc(cap);
    if (!j) { sharing_fail("Note sync: session stopped", "There is not enough memory to send the shared notes."); return NULL; }
    int o = sprintf_s(j, cap, "\"pat\":%d,\"data\":\"", p);
    b64enc(d ? d : (const unsigned char *)"", (int)(n * NOTE_SIZE), j + o);
    strcat_s(j, cap, "\"");
    return j;
}

static int notes_crdt_id(unsigned char id[16]) {
    return BCRYPT_SUCCESS(BCryptGenRandom(NULL, id, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

static int notes_crdt_budget(unsigned before, unsigned after) {
    if (g_noteSetCount - before + after > 262144) return 0;
    g_noteSetCount = g_noteSetCount - before + after;
    return 1;
}

static void notes_crdt_rebaseline(void) {
    int p, failed = 0;
    EnterCriticalSection(&g_ulockLock);
    if (!g_notesCrdt) { LeaveCriticalSection(&g_ulockLock); return; }
    for (p = 1; p < MAX_PAT; p++) {
        unsigned n, old = g_noteSets[p].count, i;
        unsigned char *d = notes_copy(p, &n), scope[16]; char hex[65];
        if (n == UINT_MAX || n > FNC_LIMIT) { free(d); failed = 1; break; }
        if (d) { notes_clear_sel(d, n); qsort(d, n, NOTE_SIZE, fnc_notecmp); }
        if (g_noteSets[p].known) {
            unsigned active;
            unsigned char *materialized = fnc_materialize(&g_noteSets[p], &active);
            int unchanged = active == n && (!n || !memcmp(materialized, d, (size_t)n * NOTE_SIZE));
            free(materialized);
            if (active == UINT_MAX) { free(d); failed = 1; break; }
            if (unchanged) { free(d); continue; }
        }
        if (!n) strcpy_s(hex, sizeof(hex), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        else if (!sha_hex(d, (size_t)n * NOTE_SIZE, hex)) { free(d); failed = 1; break; }
        for (i = 0; i < 16; i++) { char pair[3] = {hex[i * 2], hex[i * 2 + 1], 0}; scope[i] = (unsigned char)strtoul(pair, NULL, 16); }
        if (g_noteSets[p].known) {
            unsigned char chain[32];
            /* Returning to an earlier visible pattern must not reuse its retired IDs. */
            memcpy(chain, g_noteSets[p].scope, 16); memcpy(chain + 16, scope, 16);
            if (!sha_hex(chain, sizeof(chain), hex)) { free(d); failed = 1; break; }
            for (i = 0; i < 16; i++) { char pair[3] = {hex[i * 2], hex[i * 2 + 1], 0}; scope[i] = (unsigned char)strtoul(pair, NULL, 16); }
        }
        if (g_noteSetCount - old + n > 262144 || !fnc_seed(&g_noteSets[p], d, n, scope)) { free(d); failed = 1; break; }
        notes_crdt_budget(old, n); free(d);
    }
    LeaveCriticalSection(&g_ulockLock);
    if (failed) sharing_fail("Note merge: session stopped", "The shared note baseline exceeds its history or memory limit, or could not be read. Your local notes were kept.");
}

static char *notes_crdt_item(int p, const FncEntry *entries, unsigned count) {
    unsigned bytes = 0;
    unsigned char *wire = fnc_pack(&g_noteSets[p], entries, count, &bytes);
    size_t cap = 96 + ((size_t)bytes + 2) / 3 * 4;
    char *json = wire ? (char *)malloc(cap) : NULL;
    if (json) {
        int offset = sprintf_s(json, cap, "\"pat\":%d,\"crdt\":1,\"data\":\"", p);
        b64enc(wire, bytes, json + offset); strcat_s(json, cap, "\"");
    }
    free(wire);
    if (!json) sharing_fail("Note merge: session stopped", "There is not enough memory to prepare the shared note changes.");
    return json;
}

static void notes_crdt_send(int p, const FncEntry *entries, unsigned count) {
    char *item = notes_crdt_item(p, entries, count), *message;
    size_t cap;
    if (!item) return;
    cap = strlen(item) + 64; message = (char *)malloc(cap);
    if (!message) { free(item); sharing_fail("Note merge: session stopped", "There is not enough memory to send the note changes."); return; }
    sprintf_s(message, cap, "{\"t\":\"op\",\"op\":{\"kind\":\"notes.set\",%s}}", item);
    ws_send(message); free(message); free(item);
}

static int notes_crdt_capture(int p, const unsigned char *d, unsigned n, int send) {
    FncEntry *delta = NULL; unsigned changed = 0, old = g_noteSets[p].count;
    unsigned limit = 262144 - (g_noteSetCount - old);
    if (limit > FNC_LIMIT) limit = FNC_LIMIT;
    if (!fnc_capture(&g_noteSets[p], d, n, notes_crdt_id, &delta, &changed, limit)) {
        sharing_fail("Note merge: session stopped", "The note history reached its limit or a complete change could not be prepared. Your local notes were kept. Start a fresh room to reset the history.");
        return 0;
    }
    notes_crdt_budget(old, g_noteSets[p].count);
    if (changed && send) notes_crdt_send(p, delta, changed);
    free(delta);
    return !g_compatFault;
}

static void notes_crdt_receive(const QItem *it) {
    unsigned char scope[16], *local = NULL, *merged = NULL;
    const FncEntry *incoming;
    unsigned count, n = 0, old; int p = it->a, ok = 0;
    FncState next = {0};
    if (!g_notesCrdt || !fnc_unpack((const unsigned char *)it->order, (unsigned)it->mode, scope, &incoming, &count)) goto failed;
    EnterCriticalSection(&g_ulockLock);
    EnterCriticalSection(note_lock());
    if (it->b == 2 && !count && !notes_hash(p) &&
        (!g_noteSets[p].known || !g_noteSets[p].count || memcmp(scope, g_noteSets[p].scope, 16))) {
        old = g_noteSets[p].count;
        if (!fnc_seed(&g_noteSets[p], NULL, 0, scope)) goto unlock;
        notes_crdt_budget(old, 0);
        g_patSeen[p] = g_patHash[p] = 0;
        g_patChangedAt[p] = g_patDirtyAt[p] = 0;
        ok = 1; goto unlock;
    }
    if (it->b == 2 && (!g_noteSets[p].known || memcmp(scope, g_noteSets[p].scope, 16))) {
        if (!fnc_seed(&next, NULL, 0, scope) || !fnc_merge(&next, scope, incoming, count)) goto unlock;
    } else {
        if (!g_noteSets[p].known || memcmp(scope, g_noteSets[p].scope, 16)) goto unlock;
        /* Validate immutable identities before publishing any pending local recording. */
        if (!fnc_seed(&next, NULL, 0, scope) || !fnc_merge(&next, scope, g_noteSets[p].entries, g_noteSets[p].count) ||
            !fnc_merge(&next, scope, incoming, count)) goto unlock;
        fnc_free(&next);
        local = notes_copy(p, &n);
        if (n == UINT_MAX) goto unlock;
        if (local) notes_clear_sel(local, n);
        if (!notes_crdt_capture(p, local, n, 1) || !fnc_seed(&next, NULL, 0, scope) ||
            !fnc_merge(&next, scope, g_noteSets[p].entries, g_noteSets[p].count) || !fnc_merge(&next, scope, incoming, count)) goto unlock;
    }
    old = g_noteSets[p].count;
    if (g_noteSetCount - old + next.count > 262144) goto unlock;
    merged = fnc_materialize(&next, &n);
    if (n == UINT_MAX) goto unlock;
    fnc_free(&g_noteSets[p]); g_noteSets[p] = next; memset(&next, 0, sizeof(next));
    notes_crdt_budget(old, g_noteSets[p].count);
    if (notes_hash(p) == (n ? notes_fnv(merged, n) : 0)) {
        g_patSeen[p] = g_patHash[p] = n ? notes_fnv(merged, n) : 0;
        g_patChangedAt[p] = g_patDirtyAt[p] = 0; ok = 1;
    }
    else { notes_apply(p, merged, n); ok = !g_compatFault; }
unlock:
    LeaveCriticalSection(note_lock()); LeaveCriticalSection(&g_ulockLock);
    free(local); free(merged); fnc_free(&next);
    if (ok || g_compatFault) return;
failed:
    sharing_fail("Note merge: session stopped", "The incoming note history is invalid, exceeds its limit or uses a different baseline. Your local notes were kept. Reconnect and resync before continuing.");
}

static void do_notesnap(const QItem *it) {
    int p = it->a;
    unsigned n;
    unsigned char *d = notes_copy(p, &n);
    if (n == UINT_MAX) { logmsg("NOTES snapshot failed pat %d: retrying without sending an empty pattern", p); return; }
    uint64_t h = n ? notes_fnv(d, n) : 0;
    if (d) notes_clear_sel(d, n);
    if (h != g_patHash[p]) {
        if (g_notesCrdt) {
            EnterCriticalSection(&g_ulockLock);
            if (notes_crdt_capture(p, d, n, 1)) { g_patHash[p] = h; g_patDirtyAt[p] = 0; }
            LeaveCriticalSection(&g_ulockLock); free(d); return;
        }
        char key[16];
        sprintf_s(key, sizeof(key), "pat:%d", p);
        if (!unit_before_send(key, 1, p, d, n)) { free(d); unit_revert(key); return; }
        char *f = notes_json_item(p, d, n);
        if (!f) { free(d); return; }
        size_t cap = strlen(f) + 96;
        char *m = (char *)malloc(cap);
        if (!m) { free(f); free(d); sharing_fail("Note sync: session stopped", "There is not enough memory to send the shared notes."); return; }
        sprintf_s(m, cap, "{\"t\":\"op\",\"op\":{\"kind\":\"notes.set\",\"key\":\"%s\",%s}}", key, f);
        ws_send(m);
        free(m); free(f);
        g_patHash[p] = h;
        g_patDirtyAt[p] = 0;
        logmsg("NOTES sent pattern %d (%u notes)", p, n);
    }
    free(d);
}

static void do_notes(const QItem *it) {
    if (it->b) { notes_crdt_receive(it); return; }
    if (g_patSeen[it->a] != g_patHash[it->a]) {   // our unsent edit is about to be replaced
        char key[16]; sprintf_s(key, sizeof(key), "pat:%d", it->a); hint_if_held(key);
    }
    notes_apply(it->a, (const unsigned char *)it->order, (unsigned)it->mode);
    logmsg("NOTES applied pattern %d (%d notes)", it->a, it->mode);
}

// Join: patterns the leader has no notes in must be empty here too.
static void do_notesync(const QItem *it) {
    if (g_notesCrdt) return; /* Absence from a concurrent snapshot is not an observed removal. */
    const unsigned char *keep = (const unsigned char *)it->order;
    int p, n = 0;
    for (p = 1; p < MAX_PAT; p++) {
        if (keep[p] || !notes_hash(p)) continue;
        notes_apply(p, NULL, 0);
        n++;
    }
    if (n) logmsg("NOTES join: cleared %d patterns the leader has empty", n);
}

// Leader: every pattern that has notes (join / project load).
static void send_notes_full_to(const char *target) {
    size_t cap = 256, len;
    char *m = (char *)malloc(cap);
    int p, cnt = 0;
    if (!m) goto memory;
    len = sprintf_s(m, cap, "{\"t\":\"op\",\"op\":{\"kind\":\"notes.full\",\"items\":[");
    for (p = 1; p < MAX_PAT; p++) {
        unsigned n;
        /* Empty patterns also need the host's scope after a joining project load. */
        if (!g_notesCrdt && !notes_hash(p)) continue;
        unsigned char *d = notes_copy(p, &n);
        if (n == UINT_MAX) {
            free(m);
            sharing_fail("Note sync: session stopped", "The complete note snapshot could not be read. No incomplete snapshot was sent.");
            return;
        }
        g_patSeen[p] = g_patHash[p] = n ? notes_fnv(d, n) : 0;
        if (!n && !g_notesCrdt) { free(d); continue; }
        notes_clear_sel(d, n);
        char *f;
        if (g_notesCrdt) {
            EnterCriticalSection(&g_ulockLock);
            f = notes_crdt_capture(p, d, n, target != NULL) ? notes_crdt_item(p, g_noteSets[p].entries, g_noteSets[p].count) : NULL;
            LeaveCriticalSection(&g_ulockLock);
        } else f = notes_json_item(p, d, n);
        free(d);
        if (!f) { free(m); return; }
        size_t fl = strlen(f);
        if (len + fl + 8 > cap) {
            size_t next = (len + fl + 8) * 2;
            char *grown = (char *)realloc(m, next);
            if (!grown) { free(f); free(m); goto memory; }
            cap = next; m = grown;
        }
        len += sprintf_s(m + len, cap - len, "%s{%s}", cnt ? "," : "", f);
        free(f);
        cnt++;
    }
    strcat_s(m, cap, "]}}");
    ws_send_to(m, target);
    free(m);
    logmsg("NOTES full state sent: %d patterns", cnt);
    return;
memory:
    sharing_fail("Note sync: session stopped", "There is not enough memory for the complete note snapshot. No incomplete snapshot was sent.");
}

static void send_notes_full(void) { send_notes_full_to(NULL); }

// Poll thread: find patterns whose notes changed locally and have settled.
static void scan_notes(DWORD now) {
    static DWORD last = 0;
    static int pend[MAX_PAT];
    int p, np = 0, i;
    if (now - last < NOTES_SCAN_MS || g_patDepth) return;
    last = now;
    if (!g_notesReady) { notes_rebaseline(0); g_notesReady = 1; return; }
    for (p = 1; p < MAX_PAT; p++) {
        uint64_t h = notes_hash(p);
        if (h != g_patSeen[p]) { g_patSeen[p] = h; g_patChangedAt[p] = now; }
        if (h == g_patHash[p]) { g_patChangedAt[p] = g_patDirtyAt[p] = 0; continue; }
        if (!g_patDirtyAt[p]) g_patDirtyAt[p] = now;
        if (notes_suppressed(&g_patSuppress[p], now)) continue;
        if ((g_patChangedAt[p] && now - g_patChangedAt[p] >= NOTES_SETTLE_MS) ||
            now - g_patDirtyAt[p] >= NOTES_STREAM_MS) pend[np++] = p;
    }
    for (i = 0; i < np; i++) {
        enqueue_unit(T_NOTESNAP, 0, pend[i], 0, 0, NULL);
        g_patDirtyAt[pend[i]] = now;
    }
}

static unsigned char *b64dec(const char *s, size_t n, size_t *outn) {
    unsigned char *out = (unsigned char *)malloc(n / 4 * 3 + 3);
    size_t o = 0, i;
    unsigned acc = 0; int bits = 0;
    *outn = 0;
    if (!out) { sharing_fail("Shared data: session stopped", "There is not enough memory to decode the shared edit."); return NULL; }
    for (i = 0; i < n; i++) {
        int v = b64val(s[i]);
        if (v < 0) continue;
        acc = (acc << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; out[o++] = (unsigned char)((acc >> bits) & 0xff); }
    }
    *outn = o;
    return out;
}

static int shared_b64(FlJson value, FlJson *data, size_t max_bytes, size_t *bytes) {
    size_t n, padding = 0, i;
    if (value.n < 2 || value.p[0] != '"' || value.p[value.n - 1] != '"') return 0;
    data->p = value.p + 1; data->n = value.n - 2; n = data->n;
    if (n % 4 || n / 4 > (max_bytes + 2) / 3) return 0;
    if (n && data->p[n - 1] == '=') padding++;
    if (n > 1 && data->p[n - 2] == '=') padding++;
    for (i = 0; i < n - padding; i++) if (b64val(data->p[i]) < 0) return 0;
    if ((padding == 1 && (b64val(data->p[n - 2]) & 3)) ||
        (padding == 2 && (b64val(data->p[n - 3]) & 15))) return 0;
    *bytes = n / 4 * 3 - padding;
    return *bytes <= max_bytes;
}

static int notes_decode_item(FlJson item, int full, QItem *task) {
    FlJson value, data; uint64_t number; size_t bytes, n;
    int crdt = fj_get(item, "crdt", &value);
    memset(task, 0, sizeof(*task));
    if ((crdt && (!g_notesCrdt || !fj_is(value, "1"))) || (!crdt && g_notesCrdt) ||
        !fj_get(item, "pat", &value) || !fc_uint(value, &number) || !number || number >= MAX_PAT ||
        !fj_get(item, "data", &value) || !shared_b64(value, &data,
            crdt ? FNC_HEADER + FNC_LIMIT * FNC_ENTRY : 1000000 * NOTE_SIZE, &bytes)) return 0;
    task->order = (int *)b64dec(data.p, data.n, &n);
    if (!task->order) return 0;
    if (crdt) {
        unsigned char scope[16]; const FncEntry *entries; unsigned count;
        if (!fnc_unpack((unsigned char *)task->order, (unsigned)n, scope, &entries, &count)) goto invalid;
    } else if (n % NOTE_SIZE) goto invalid;
    task->type = T_NOTES; task->a = (int)number;
    task->mode = (int)(crdt ? n : n / NOTE_SIZE); task->b = crdt ? (full ? 2 : 1) : 0;
    return 1;
invalid:
    free(task->order); task->order = NULL; return 0;
}

static void on_notes(const char *m, int full) {
    FlJson root = {m, strlen(m)}, op, items, item;
    const char *p, *end, *start;
    unsigned char *keep = NULL;
    QItem *tasks = NULL, one = {0};
    unsigned count = 0, i, history = 0;
    LONG generation = session_generation();
    if (!fj_get(root, "op", &op)) goto invalid;
    if (!full) {
        if (!notes_decode_item(op, 0, &one)) goto invalid;
        enqueue(&one); return;
    }
    if (!fj_get(op, "items", &items) || items.n < 2 || items.p[0] != '[') goto invalid;
    keep = (unsigned char *)calloc(MAX_PAT, 1);
    tasks = (QItem *)calloc(MAX_PAT + 1, sizeof(*tasks));
    if (!keep || !tasks) goto invalid;
    p = items.p + 1; end = items.p + items.n - 1; fj_space(&p, end);
    while (p < end) {
        start = p;
        if (count == MAX_PAT - 1 || !fj_value(&p, end, 0)) goto invalid;
        item.p = start; item.n = (size_t)(p - start);
        if (!notes_decode_item(item, 1, &tasks[count])) goto invalid;
        count++;
        if (keep[tasks[count - 1].a]) goto invalid;
        keep[tasks[count - 1].a] = 1;
        if (g_notesCrdt) {
            history += ((unsigned)tasks[count - 1].mode - FNC_HEADER) / FNC_ENTRY;
            if (history > 262144) goto invalid;
        }
        fj_space(&p, end);
        if (p < end) { if (*p++ != ',') goto invalid; fj_space(&p, end); if (p == end) goto invalid; }
    }
    tasks[count].type = T_NOTESYNC; tasks[count].order = (int *)keep; count++; keep = NULL;
    EnterCriticalSection(&g_qLock);
    if (generation != g_netGen || g_compatFault) { LeaveCriticalSection(&g_qLock); goto cleanup; }
    if (count > (unsigned)((g_qh + QCAP - g_qt - 1) % QCAP)) { LeaveCriticalSection(&g_qLock); goto invalid; }
    for (i = 0; i < count; i++) {
        tasks[i].sessionGen = generation; g_q[g_qt] = tasks[i]; g_qt = (g_qt + 1) % QCAP;
    }
    LeaveCriticalSection(&g_qLock);
    free(tasks);
    if (g_mainWnd) PostMessageW(g_mainWnd, WM_NULL, 0, 0);
    return;
invalid:
    sharing_fail("Shared notes: session stopped", "The complete note snapshot is invalid, exceeds its limits or could not be queued. No partial snapshot was queued. Reconnect and resync before continuing.");
cleanup:
    for (i = 0; i < count; i++) discard_task(&tasks[i]);
    free(tasks); free(keep);
}

// ---------------- playlist clips ----------------
// Unit = the clip list of one arrangement (records = FLP event 233 layout + runtime tail).
// Same scheme as notes: hash from the poll thread, copy/replace on the main thread under
// FL's note lock, then FL's own playlist refresh (what its clip-properties dialog calls).
// Hashes ignore the selection bit and the per-instance clip id, and are order-independent
// (FL orders clips at the same position by insertion, which differs between peers).
static uint64_t g_clipHash = 0, g_clipSeen = 0;
static DWORD    g_clipChangedAt = 0;
static volatile DWORD g_clipSuppress = 0;
static int      g_clipArr = -1;                  // arrangement the baseline belongs to

static int clip_cmp(const void *a, const void *b) { return memcmp(a, b, CLIP_SIZE); }

static size_t clip_native_size(void) {
    return flim_profile_fl24(&g_fl) ? FLIM_CLIP_FL24_SIZE : FLIM_CLIP_WIRE_SIZE;
}

static unsigned char *clips_from_native(const unsigned char *native, unsigned n) {
    unsigned i;
    size_t stride = clip_native_size();
    unsigned char *wire;
    if (!n || n > 200000 || !native) return NULL;
    wire = (unsigned char *)malloc((size_t)n * CLIP_SIZE);
    if (!wire) return NULL;
    __try {
        for (i = 0; i < n; i++)
            if (!flim_clip_from_native(wire + (size_t)i * CLIP_SIZE, native + (size_t)i * stride, stride)) {
                free(wire); return NULL;
            }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        free(wire); return NULL;
    }
    return wire;
}

static char *arr_clips(int arr) {
    char *arrs = *(char **)(g_flBase + (ARRS_VA - IMG_BASE));
    if (!arrs || arr < 0 || arr >= (int)*(int64_t *)(arrs - 8)) return NULL;
    char *a = *(char **)(arrs + (size_t)arr * 8);
    return a ? *(char **)(a + ARR_CLIPS) : NULL;
}
static int cur_arr(void) {
    __try { return *(int *)(g_flBase + (ARRCUR_VA - IMG_BASE)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
}

// Masked, sorted copy -> hash. d may be modified (it is a private copy).
static uint64_t clips_fnv(unsigned char *d, unsigned n) {
    unsigned i;
    if (!n) return 0;
    for (i = 0; i < n; i++) {
        unsigned char *r = d + (size_t)i * CLIP_SIZE;
        r[CLIP_SEL_OFS] &= (unsigned char)~CLIP_SEL_BIT;
        memset(r + CLIP_ID_OFS, 0, 4);
    }
    qsort(d, n, CLIP_SIZE, clip_cmp);
    return fnv64(d, (size_t)n * CLIP_SIZE);
}

// Called from the poll thread and the main thread: private buffer per call.
static uint64_t clips_hash(int arr) {
    unsigned char *buf = NULL;
    uint64_t h = 0;
    EnterCriticalSection(note_lock());
    __try {
        char *ca = arr_clips(arr);
        unsigned n = ca ? *(unsigned *)(ca + CLIPS_COUNT) : 0;
        if (n > 200000) h = 1;
        else if (n) {
            buf = clips_from_native(*(unsigned char **)(ca + CLIPS_DATA), n);
            h = buf ? clips_fnv(buf, n) : 1;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { h = 1; }
    LeaveCriticalSection(note_lock());
    free(buf);
    return h;
}

static void clips_rebaseline(void) {
    g_clipArr = cur_arr();
    g_clipSeen = g_clipHash = clips_hash(g_clipArr);
    g_clipChangedAt = 0;
}

// Copy of an arrangement's clips (main thread, under FL's note lock).
static unsigned char *clips_copy(int arr, unsigned *n) {
    unsigned char *buf = NULL;
    *n = UINT_MAX;
    EnterCriticalSection(note_lock());
    __try {
        char *ca = arr_clips(arr);
        unsigned c = ca ? *(unsigned *)(ca + CLIPS_COUNT) : 0;
        if (ca && !c) *n = 0;
        if (c && c <= 200000) {
            buf = clips_from_native(*(unsigned char **)(ca + CLIPS_DATA), c);
            if (buf) *n = c;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { free(buf); buf = NULL; *n = UINT_MAX; }
    LeaveCriticalSection(note_lock());
    return buf;
}

static void playlist_refresh(void) {
    __try {
        void *form = **(void ***)(g_flBase + (PLFORM_VA - IMG_BASE));
        if (form && flim_profile_fl24(&g_fl)) {
            void *grid = *(void **)((char *)form + g_fl.PR_GRID);
            gridrefresh_t invalidate = (gridrefresh_t)(g_flBase + (PLREFRESH_VA - IMG_BASE));
            if (grid) {
                invalidate(grid);
                ((void (*)(void))(g_flBase + (0x118a8c0 - IMG_BASE)))();
            }
            grid = *(void **)((char *)form + g_fl.PL_GRID);
            if (grid) invalidate(grid);
        } else if (form) ((formfn_t)(g_flBase + (PLREFRESH_VA - IMG_BASE)))(form);
    } __except (EXCEPTION_EXECUTE_HANDLER) { logmsg("CLIPS refresh faulted"); }
}

typedef struct { unsigned char rec[CLIP_SIZE]; unsigned index, selected; } ClipApplyRef;
static int clip_apply_cmp(const void *a, const void *b) {
    const ClipApplyRef *x = (const ClipApplyRef *)a, *y = (const ClipApplyRef *)b;
    int order = memcmp(x->rec, y->rec, CLIP_SIZE);
    if (order) return order;
    if (x->selected != y->selected) return x->selected ? -1 : 1;
    return x->index < y->index ? -1 : x->index > y->index;
}
static void clip_apply_ref(ClipApplyRef *ref, const unsigned char *data, unsigned n) {
    unsigned i;
    for (i = 0; i < n; i++) {
        memcpy(ref[i].rec, data + (size_t)i * CLIP_SIZE, CLIP_SIZE);
        ref[i].selected = !!(ref[i].rec[CLIP_SEL_OFS] & CLIP_SEL_BIT);
        ref[i].rec[CLIP_SEL_OFS] &= (unsigned char)~CLIP_SEL_BIT;
        memset(ref[i].rec + CLIP_ID_OFS, 0, 4); ref[i].index = i;
    }
    if (n) qsort(ref, n, sizeof(*ref), clip_apply_cmp);
}
/* Match duplicates once, keeping this computer's selected copies first. */
static int clips_apply_plan(const unsigned char *old, unsigned c, unsigned char *in, unsigned n, int *same) {
    ClipApplyRef *before = c ? (ClipApplyRef *)malloc((size_t)c * sizeof(*before)) : NULL;
    ClipApplyRef *after = n ? (ClipApplyRef *)malloc((size_t)n * sizeof(*after)) : NULL;
    unsigned a = 0, b = 0, matched = 0;
    *same = 0;
    if ((c && !before) || (n && !after)) { free(before); free(after); return 0; }
    clip_apply_ref(before, old, c); clip_apply_ref(after, in, n);
    while (a < c && b < n) {
        int order = memcmp(before[a].rec, after[b].rec, CLIP_SIZE);
        if (!order) {
            if (before[a].selected) in[(size_t)after[b].index * CLIP_SIZE + CLIP_SEL_OFS] |= CLIP_SEL_BIT;
            a++; b++; matched++;
        } else if (order < 0) a++; else b++;
    }
    *same = matched == c && c == n;
    free(before); free(after); return 1;
}

static int clips_apply(int arr, const unsigned char *recs, unsigned n) {
    unsigned i, j;
    size_t stride = clip_native_size();
    unsigned char *in, *native, *check;
    unsigned char *old = NULL;
    int applied = 0, faulted = 0, changed = 0;
    if (n > 200000 || !flim_clips_compatible(recs, n, stride)) {
        compat_fail("A playlist clip uses data this FL build cannot preserve. The session stopped before replacing any clips.");
        return 0;
    }
    in = n ? (unsigned char *)malloc((size_t)n * CLIP_SIZE) : NULL;
    native = n ? (unsigned char *)malloc((size_t)n * stride) : NULL;
    check = n ? (unsigned char *)malloc((size_t)n * CLIP_SIZE) : NULL;
    if (n && (!in || !native || !check)) { free(in); free(native); free(check); goto failed; }
    for (i = 0; i < n; i++) {
        memcpy(in + (size_t)i * CLIP_SIZE, recs + (size_t)i * CLIP_SIZE, CLIP_SIZE);
        in[(size_t)i * CLIP_SIZE + CLIP_SEL_OFS] &= (unsigned char)~CLIP_SEL_BIT;
    }
    EnterCriticalSection(note_lock());
    __try {
        char *ca = arr_clips(arr);
        if (ca) {
            void **vmt = *(void ***)ca;
            clipadd_t add = (clipadd_t)vmt[CLIPADD_VSLOT];
            clippurge_t purge = (clippurge_t)vmt[CLIPPURGE_VSLOT];
            unsigned c = *(unsigned *)(ca + CLIPS_COUNT);
            unsigned char *d = *(unsigned char **)(ca + CLIPS_DATA);
            int same;
            if (c > 200000) __leave;
            old = c ? clips_from_native(d, c) : NULL;
            if ((c && !old) || !clips_apply_plan(old, c, in, n, &same)) __leave;
            if (same) { applied = 1; __leave; }
            for (i = 0; i < n; i++)
                if (!flim_clip_to_native(native + (size_t)i * stride, in + (size_t)i * CLIP_SIZE, stride)) __leave;
            for (j = 0; j < c; j++) *(int32_t *)(d + (size_t)j * stride + CLIP_DEL_OFS) = -1;
            if (c) purge(ca);
            for (i = 0; i < n; i++) add(ca, native + (size_t)i * stride);
            changed = 1;
            applied = *(unsigned *)(ca + CLIPS_COUNT) == n;
            if (applied && n) {
                d = *(unsigned char **)(ca + CLIPS_DATA);
                for (i = 0; i < n; i++) if (!flim_clip_from_native(check + (size_t)i * CLIP_SIZE, d + (size_t)i * stride, stride)) { applied = 0; break; }
                if (applied) {
                    clips_fnv(in, n); clips_fnv(check, n);
                    applied = !memcmp(in, check, (size_t)n * CLIP_SIZE);
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { faulted = 1; logmsg("CLIPS apply faulted arr %d", arr); }
    LeaveCriticalSection(note_lock());
    if (applied) unit_agreed(0, arr, in, n);
    free(old); free(in); free(native); free(check);
    if (!applied || faulted) goto failed;
    if (changed) playlist_refresh();
    if (arr == g_clipArr) { g_clipSeen = g_clipHash = clips_hash(arr); g_clipChangedAt = 0; }
    g_clipSuppress = GetTickCount() + NOTES_SETTLE_MS;
    return 1;
failed:
    compat_fail("FL could not apply or verify a playlist edit. Sharing paused to avoid continuing with different clip lists. Your project remains open.");
    return 0;
}

static void do_clipsnap(const QItem *it) {
    unsigned n;
    unsigned char *d = clips_copy(it->a, &n);
    if (n > 200000) return;
    unsigned char *h = n ? (unsigned char *)malloc((size_t)n * CLIP_SIZE) : NULL;
    uint64_t hv;
    unsigned i;
    if (n && !h) { free(d); return; }
    if (h) memcpy(h, d, (size_t)n * CLIP_SIZE);
    hv = n ? clips_fnv(h, n) : 0;
    free(h);
    if (it->a == g_clipArr && hv != g_clipHash) {
        char key[16];
        for (i = 0; i < n; i++) d[(size_t)i * CLIP_SIZE + CLIP_SEL_OFS] &= (unsigned char)~CLIP_SEL_BIT;
        sprintf_s(key, sizeof(key), "clips:%d", it->a);
        size_t cap = 96 + ((size_t)n * CLIP_SIZE + 2) / 3 * 4;
        char *m = (char *)malloc(cap);
        if (!m) { free(d); return; }
        if (!unit_before_send(key, 0, it->a, d, n)) { free(m); free(d); unit_revert(key); return; }
        int o = sprintf_s(m, cap, "{\"t\":\"op\",\"op\":{\"kind\":\"clips.set\",\"key\":\"%s\",\"arr\":%d,\"data\":\"", key, it->a);
        b64enc(d ? d : (const unsigned char *)"", (int)(n * CLIP_SIZE), m + o);
        strcat_s(m, cap, "\"}}");
        ws_send(m);
        free(m);
        g_clipHash = hv;
        logmsg("CLIPS sent arrangement %d (%u clips)", it->a, n);
    }
    free(d);
}

static void do_clips(const QItem *it) {
    if (it->a == g_clipArr && g_clipSeen != g_clipHash) {
        char key[16]; sprintf_s(key, sizeof(key), "clips:%d", it->a); hint_if_held(key);
    }
    if (clips_apply(it->a, (const unsigned char *)it->order, (unsigned)it->mode))
        logmsg("CLIPS applied arrangement %d (%d clips)", it->a, it->mode);
}

// A locally added channel whose chan.add has not been queued yet (poll thread).
static int chan_add_pending(void) {
    int i;
    for (i = 0; i < g_nChKnown && i < MAX_CH; i++) if (g_chU[i].addAt) return 1;
    return 0;
}

// Poll thread: the current arrangement's clips changed locally and settled?
static void scan_clips(DWORD now) {
    static DWORD last = 0;
    int arr;
    uint64_t h;
    if (now - last < NOTES_SCAN_MS || g_patDepth) return;
    last = now;
    arr = cur_arr();
    if (arr != g_clipArr) { clips_rebaseline(); return; }       // switched arrangement: new baseline
    h = clips_hash(arr);
    if (h != g_clipSeen) { g_clipSeen = h; g_clipChangedAt = now; }
    if (g_clipChangedAt && now - g_clipChangedAt >= NOTES_SETTLE_MS) {
        // a new automation clip / audio clip channel: its chan.add must go out first
        if (chan_add_pending()) return;
        if (notes_suppressed(&g_clipSuppress, now)) return;
        if (g_clipSeen != g_clipHash) enqueue_unit(T_CLIPSNAP, 0, arr, 0, 0, NULL);
        else g_clipChangedAt = 0;
    }
}

// Inbound clips.set (recv thread).
static void on_clips_set(const char *m) {
    FlJson root = {m, strlen(m)}, op, value, data;
    uint64_t arr;
    size_t n = 0, bytes;
    if (!fj_get(root, "op", &op)) op = root;
    if (!fj_get(op, "arr", &value) || !fc_uint(value, &arr) || arr > INT_MAX ||
        !fj_get(op, "data", &value) || !shared_b64(value, &data, 200000 * CLIP_SIZE, &bytes) ||
        bytes % CLIP_SIZE) goto invalid;
    unsigned char *recs = b64dec(data.p, data.n, &n);
    if (!recs) return;
    QItem it; memset(&it, 0, sizeof(it));
    it.type = T_CLIPS; it.a = (int)arr; it.mode = (int)(n / CLIP_SIZE); it.order = (int *)recs;
    enqueue(&it);
    return;
invalid:
    sharing_fail("Shared clips: session stopped", "The shared playlist data is incomplete or invalid. Your local clips were kept. Reconnect and resync before continuing to share.");
}

// ---------------- names, colors, mixer routing ("meta") ----------------
// Small per-entity state: mixer track name + color, mixer track routing (sends on/off +
// level), channel name + color, pattern name + color + length, playlist track name + color
// (every arrangement). Same scheme as notes: hashes from the poll thread, sent once settled,
// applied on the main thread with FL's own setters (the ones its Python API calls). Joins and
// project loads carry all of this in the .flp, so only live edits travel. No locks (renames
// are rare); if both sides change the same thing at once, the leader's value wins.
#define MIXNAME_VA (g_fl.MIXNAME)    // SetMixerTrackName(track, name, 1): also renames linked playlist tracks
#define MIXCOLOR_VA (g_fl.MIXCOLOR)    // SetMixerTrackColor(track record, color)
#define UIUPDATE_VA (g_fl.UIUPDATE)     // UIUpdate(what, 0); 0x18 = mixer (what FL calls after a mixer color)
#define MIXOBJ_VA (g_fl.MIXOBJ)    // global -> var -> mixer object (routing calls take it)
#define SETROUTE_VA (g_fl.SETROUTE)    // SetRoute(mixer, src, dst, on, 1) -> int
#define ROUTEUPD_VA (g_fl.ROUTEUPD)    // RoutingChanged(mixer): after route / send level edits
#define MIX_NAME      0x0c         // mixer track: UnicodeString name ('' = "Insert N")
#define MIX_COLOR     0x04
#define MIX_ROUTE     (g_fl.MIX_ROUTE) // + dst*8: int send level (12800 = 100%); +4: byte, 1 = routed
#define MIX_ROUTE_MAX 502
#define CH_NAME       0x50         // channel object: UnicodeString name
#define CH_COLOR      0x78
#define CH_SETNAME_VSLOT  (0x70 / 8)   // channel vmt: SetName(self, name)
#define CH_SETCOLOR_VSLOT (0x78 / 8)   //              SetColor(self, color)
#define PAT_NAME      0x00         // pattern record: UnicodeString name ('' = "Pattern N")
#define PAT_COLOR     0x08
#define PAT_LENGTH    0x10         // int, -1 = automatic
#define PATNAME_VA (g_fl.PATNAME)    // SetPatternName(pattern, name)
#define PATCOLOR_VA (g_fl.PATCOLOR)    // SetPatternColor(pattern, color): also sets the "custom color" flag
#define PATREFRESH_VA (g_fl.PATREFRESH)     // what FL calls on (playlist form +0xd00) after a pattern rename
#define PLFORM_PATS   (g_fl.PLFORM_PATS)
#define PL_TRK_STRIDE 0x114        // arrangement object: playlist track t (1..500) at + t*0x114
#define PL_TRK_NAME   0x24
#define PL_TRK_COLOR  0x2c
#define PL_TRK_MAX    500
#define PLTRACK_VA (g_fl.PLTRACK)    // SetPlaylistTrack(arrangement, track, name, color)
// playlist markers (per arrangement) and the project time signature
#define ARR_MARKERS   0x21c48      // arrangement object: dynamic array of marker records (stride 0x34)
#define MARK_SIZE     0x34         // +0 position, +4 action (8 = time signature), +8 UnicodeString name,
#define MARK_TAIL     0x10         //   +0x10.. plain data (+0x10 numerator, +0x11 denominator)
#define MARK_MAX      4096
#define MARKADD_VA (g_fl.MARKADD)     // MarkerListAdd(&list, pos, name, action, num, den): appends a record
#define MARKTYPE_VA (g_fl.MARKTYPE)     // global -> RTTI of the marker record array (for DynArraySetLength)
#define DYNSETLEN_VA (g_fl.DYNSETLEN)     // Delphi DynArraySetLength(&arr, typeinfo, 1, newLength)
#define MARKREFRESH_VA (g_fl.MARKREFRESH)    // MarkersChanged(playlist form): sort, redraw, time signature from markers
#define PL_MARKSEL    (g_fl.PL_MARKSEL)        // playlist form: index of the marker being edited (-1 = none)
// pattern markers (piano roll): same records, one list per pattern; a pattern's own time signature
// (pattern menu > Time signature) is an action-8 marker at 0 in this list
#define PAT_MARKERS   0x30         // pattern record: dynamic array of marker records
#define MARKSORT_VA (g_fl.MARKSORT)     // MarkerListSort(&list): sort + number them (builds the pattern's +0x38 table)
#define PATLENUPD_VA (g_fl.PATLENUPD)    // UpdatePatternLength(pattern, 0): bar length from the pattern's time signature
#define PATMARKS_VA (g_fl.PATMARKS)    // PatternMarkersChanged(pattern record): redraws the editors showing them
#define SONGLOCK_VA (g_fl.SONGLOCK)    // global: CRITICAL_SECTION* FL holds while editing markers / time signature
#define MODIFIED_VA (g_fl.MODIFIED)    // SetModified(1): project changed
#define TSNUM_VA (g_fl.TSNUM)    // global -> int: project time signature numerator
#define TSDEN_VA (g_fl.TSDEN)    //                                       denominator
#define TSSET_VA (g_fl.TSSET)    // TimeSigFromControls(main form): what the toolbar's time settings call
#define TSCTLS_VA (g_fl.TSCTLS)    // TimeSigToControls(main form): controls from the two globals
#define META_ARR_MAX  8
#define META_MAX      (META_ARR_MAX * 512)
#define META_SCAN_MS  150
#define META_SETTLE_MS 300         // some dialogs rename per keystroke: send once it stops
#define META_BULK     24           // this many entities changing at once = project load / pattern insert
#define META_CONFLICT_MS 1500      // leader: a remote change this soon after our own send of the same thing loses

typedef void (*mixname_t)(int track, const wchar_t *name, uint8_t update);
typedef void (*mixcolor_t)(void *rec, uint32_t color);
typedef void (*uiupdate_t)(int what, uint64_t flag);
typedef int  (*setroute_t)(void *mixer, int src, int dst, int on, int flag);
typedef void (*mixerfn_t)(void *mixer);
typedef void (*chsetname_t)(void *ch, const wchar_t *name);
typedef void (*chsetcolor_t)(void *ch, uint32_t color);
typedef void (*patname_t)(int pat, const wchar_t *name);
typedef void (*patcolor_t)(int pat, uint32_t color);
typedef void (*patrefresh_t)(void *obj, uint8_t a, uint8_t b);
typedef void (*pltrack_t)(void *arr, int track, const wchar_t *name, uint32_t color);
typedef void (*markadd_t)(void *list, int pos, const wchar_t *name, int action, uint8_t num, uint8_t den);
typedef void (*dynsetlen_t)(void *arr, void *typeinfo, int64_t dims, int64_t len);
typedef void (*setmod_t)(int on);
typedef void (*patlenupd_t)(int pat, int flag);

enum { M_MIX, M_ROUTE, M_CHAN, M_PAT, M_PLT, M_MARK, M_TSIG, M_PMARK, M_NTYPES };
static const char *const M_TAG[M_NTYPES] = { "mx", "rt", "ch", "pt", "pl", "mk", "ts", "pm" };
static uint64_t g_mHash[M_NTYPES][META_MAX];   // last state sent or applied
static uint64_t g_mSeen[M_NTYPES][META_MAX];   // last state the scanner saw
static DWORD    g_mAt[M_NTYPES][META_MAX];     // when g_mSeen last moved (0 = settled/handled)
static DWORD    g_mSentAt[M_NTYPES][META_MAX];
static volatile LONG g_metaReady = 0;

static uint64_t fnv_add(uint64_t h, const void *p, size_t n) {
    const unsigned char *b = (const unsigned char *)p;
    size_t i;
    for (i = 0; i < n; i++) { h ^= b[i]; h *= 1099511628211ull; }
    return h;
}
// Length of a Delphi UnicodeString (NULL = '').
static int ustr_len(const wchar_t *s) {
    int n = s ? *(const int32_t *)((const char *)s - 4) : 0;
    return n < 0 || n > 4096 ? 0 : n;
}
static uint64_t fnv_ustr(uint64_t h, const wchar_t *s) {
    int n = ustr_len(s);
    h = fnv_add(h, &n, 4);
    return n ? fnv_add(h, s, (size_t)n * 2) : h;
}
static int ustr_eq(const wchar_t *cur, const wchar_t *w) {
    int n = ustr_len(cur);
    return n == (int)wcslen(w) && (n == 0 || memcmp(cur, w, (size_t)n * 2) == 0);
}

static int meta_cap(int type) {
    switch (type) {
    case M_MIX: case M_ROUTE: return MAX_MIX;
    case M_CHAN: return MAX_CH;
    case M_PAT: case M_PMARK: return MAX_PAT;
    case M_MARK: return META_ARR_MAX;
    case M_TSIG: return 1;
    default: return META_MAX;
    }
}
static char *mix_rec(int t) { return *(char **)(g_flBase + (MIXARR_VA - IMG_BASE)) + (size_t)t * MIX_STRIDE; }
static char *pat_rec(int p) { return *(char **)(g_flBase + (PATARR_VA - IMG_BASE)) + (size_t)p * PAT_STRIDE; }
static int arr_count(void) {
    __try {
        char *arrs = *(char **)(g_flBase + (ARRS_VA - IMG_BASE));
        int n = arrs ? (int)*(int64_t *)(arrs - 8) : 0;
        return n < 0 ? 0 : (n > META_ARR_MAX ? META_ARR_MAX : n);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
static char *arr_obj(int arr) {
    char *arrs = *(char **)(g_flBase + (ARRS_VA - IMG_BASE));
    return *(char **)(arrs + (size_t)arr * 8);
}
// Marker array of an arrangement (Delphi dynamic array: length as int64 at -8).
static char **mark_list(int arr) { return (char **)(arr_obj(arr) + ARR_MARKERS); }
// M_MARK: arrangement i's markers; M_PMARK: pattern i's
static char **marks_of(int type, int i) { return type == M_MARK ? mark_list(i) : (char **)(pat_rec(i) + PAT_MARKERS); }
static int mark_count(const char *a) {
    int64_t n = a ? *(const int64_t *)(a - 8) : 0;
    return n < 0 || n > MARK_MAX ? 0 : (int)n;
}
static int *ts_num(void) { return *(int **)(g_flBase + (TSNUM_VA - IMG_BASE)); }
static int *ts_den(void) { return *(int **)(g_flBase + (TSDEN_VA - IMG_BASE)); }
static CRITICAL_SECTION *song_lock(void) { return *(CRITICAL_SECTION **)(g_flBase + (SONGLOCK_VA - IMG_BASE)); }

// i = arrangement * 512 + track (1..500)
static char *pl_track(int i) {
    char *a = arr_obj(i / 512);
    return a ? a + (size_t)(i % 512) * PL_TRK_STRIDE : NULL;
}
static int meta_valid(int type, int i) {
    switch (type) {
    case M_MIX: case M_ROUTE: return i >= 0 && i < mix_count();
    case M_CHAN: return i >= 0 && i < g_nChKnown;
    case M_PAT: case M_PMARK: return i >= 1 && i < MAX_PAT;
    case M_MARK: return i >= 0 && i < arr_count();
    case M_TSIG: return i == 0;
    default: return i % 512 >= 1 && i % 512 <= PL_TRK_MAX && i / 512 < arr_count();
    }
}

// Hash of one entity's synced fields (0 = absent). Any thread: SEH-guarded unlocked reads
// (a torn read is just a change that settles).
static uint64_t meta_hash(int type, int i) {
    uint64_t h = 1469598103934665603ull;
    if (!meta_valid(type, i)) return 0;
    __try {
        switch (type) {
        case M_MIX: {
            char *r = mix_rec(i);
            h = fnv_add(h, r + MIX_COLOR, 4);
            h = fnv_ustr(h, *(wchar_t **)(r + MIX_NAME));
            break; }
        case M_ROUTE: {
            char *r = mix_rec(i);
            int d, nm = mix_count();
            for (d = 0; d < nm && d < MIX_ROUTE_MAX; d++) {
                unsigned char on = (unsigned char)r[MIX_ROUTE + d * 8 + 4];
                h = fnv_add(h, &on, 1);
                if (on) h = fnv_add(h, r + MIX_ROUTE + d * 8, 4);
            }
            break; }
        case M_CHAN: {
            void **items;
            int n = chan_list(&items);
            if (!items || i >= n) return 0;
            h = fnv_add(h, (char *)items[i] + CH_COLOR, 4);
            h = fnv_ustr(h, *(wchar_t **)((char *)items[i] + CH_NAME));
            break; }
        case M_PAT: {
            char *r = pat_rec(i);
            h = fnv_add(h, r + PAT_COLOR, 4);
            h = fnv_add(h, r + PAT_LENGTH, 4);
            h = fnv_ustr(h, *(wchar_t **)(r + PAT_NAME));
            break; }
        case M_MARK: case M_PMARK: {
            const char *a = *marks_of(type, i);
            int k, n = mark_count(a);
            h = fnv_add(h, &n, 4);
            for (k = 0; k < n; k++) {
                const char *r = a + (size_t)k * MARK_SIZE;
                h = fnv_add(h, r, 8);
                h = fnv_add(h, r + MARK_TAIL, MARK_SIZE - MARK_TAIL);
                h = fnv_ustr(h, *(wchar_t **)(r + 8));
            }
            break; }
        case M_TSIG:
            h = fnv_add(h, ts_num(), 4);
            h = fnv_add(h, ts_den(), 4);
            break;
        default: {
            char *r = pl_track(i);
            if (!r) return 0;
            h = fnv_add(h, r + PL_TRK_COLOR, 4);
            h = fnv_ustr(h, *(wchar_t **)(r + PL_TRK_NAME));
            break; }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 1; }
    return h > 2 ? h : 3;
}

static void meta_rebaseline(int channels_only) {
    int t, i;
    for (t = 0; t < M_NTYPES; t++)
        if (!channels_only || t == M_CHAN)
        for (i = 0; i < meta_cap(t); i++) { g_mSeen[t][i] = g_mHash[t][i] = meta_hash(t, i); g_mAt[t][i] = 0; }
}

static void meta_observe(DWORD now) {
    int t, i;
    for (t = 0; t < M_NTYPES; t++)
        for (i = 0; i < meta_cap(t); i++) {
            uint64_t h = meta_hash(t, i);
            if (h != g_mSeen[t][i]) { g_mSeen[t][i] = h; g_mAt[t][i] = now; }
        }
}

// After applying a remote change: FL's setters touch other entities too (a mixer rename
// renames its linked playlist tracks). Take those as known, except where a local edit is pending.
static void meta_absorb(void) {
    int t, i;
    for (t = 0; t < M_NTYPES; t++)
        for (i = 0; i < meta_cap(t); i++) {
            if (g_mAt[t][i] || g_mSeen[t][i] != g_mHash[t][i]) continue;
            g_mSeen[t][i] = g_mHash[t][i] = meta_hash(t, i);
        }
}

// {"t":"op","op":{"kind":"meta.set","e":"<tag>","i":N, ...fields}}; name = base64 UTF-16LE.
// Main thread. NULL if the entity is gone.
static char *meta_json(int t, int i) {
    size_t cap = 32768;
    char *m;
    if (t == M_MARK || t == M_PMARK) {
        __try { cap += (size_t)mark_count(*marks_of(t, i)) * (64 + 2 * ((MARK_SIZE - MARK_TAIL + 2) / 3 * 4) + 4 * 256); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return NULL; }
    }
    m = (char *)malloc(cap);
    if (!m) { sharing_fail("Shared details: sharing paused", "There is not enough memory to send the shared project details."); return NULL; }
    int o = sprintf_s(m, cap, "{\"t\":\"op\",\"op\":{\"kind\":\"meta.set\",\"e\":\"%s\",\"i\":%d", M_TAG[t], i);
    __try {
        const wchar_t *name = NULL;
        uint32_t color = 0;
        char *r = NULL;
        switch (t) {
        case M_MIX: r = mix_rec(i); color = *(uint32_t *)(r + MIX_COLOR); name = *(wchar_t **)(r + MIX_NAME); break;
        case M_CHAN: {
            void **items;
            int n = chan_list(&items);
            if (!items || i >= n) { free(m); return NULL; }
            r = (char *)items[i]; color = *(uint32_t *)(r + CH_COLOR); name = *(wchar_t **)(r + CH_NAME);
            break; }
        case M_PAT:
            r = pat_rec(i); color = *(uint32_t *)(r + PAT_COLOR); name = *(wchar_t **)(r + PAT_NAME);
            o += sprintf_s(m + o, cap - o, ",\"l\":%d", *(int32_t *)(r + PAT_LENGTH));
            break;
        case M_PLT:
            r = pl_track(i);
            if (!r) { free(m); return NULL; }
            color = *(uint32_t *)(r + PL_TRK_COLOR); name = *(wchar_t **)(r + PL_TRK_NAME);
            break;
        case M_ROUTE: {
            int d, k = 0, nm = mix_count();
            r = mix_rec(i);
            o += sprintf_s(m + o, cap - o, ",\"r\":[");
            for (d = 0; d < nm && d < MIX_ROUTE_MAX; d++)
                if (r[MIX_ROUTE + d * 8 + 4])
                    o += sprintf_s(m + o, cap - o, "%s[%d,%d]", k++ ? "," : "", d, *(int32_t *)(r + MIX_ROUTE + d * 8));
            o += sprintf_s(m + o, cap - o, "]");
            break; }
        case M_MARK: case M_PMARK: {
            // "mk":[[pos,action,"<tail b64>","<name b64>"],...]
            const char *a = *marks_of(t, i);
            int k, n = mark_count(a);
            o += sprintf_s(m + o, cap - o, ",\"mk\":[");
            for (k = 0; k < n; k++) {
                const char *r = a + (size_t)k * MARK_SIZE;
                const wchar_t *nm = *(wchar_t **)(r + 8);
                int nl = ustr_len(nm);
                if (nl > 255) nl = 255;
                o += sprintf_s(m + o, cap - o, "%s[%d,%d,\"", k ? "," : "", *(int32_t *)r, *(int32_t *)(r + 4));
                b64enc((const unsigned char *)r + MARK_TAIL, MARK_SIZE - MARK_TAIL, m + o);
                o += (int)strlen(m + o);
                o += sprintf_s(m + o, cap - o, "\",\"");
                b64enc(nl ? (const unsigned char *)nm : (const unsigned char *)"", nl * 2, m + o);
                o += (int)strlen(m + o);
                o += sprintf_s(m + o, cap - o, "\"]");
            }
            o += sprintf_s(m + o, cap - o, "]");
            break; }
        case M_TSIG:
            o += sprintf_s(m + o, cap - o, ",\"nu\":%d,\"de\":%d", *ts_num(), *ts_den());
            break;
        }
        if (t != M_ROUTE && t != M_MARK && t != M_TSIG && t != M_PMARK) {
            int nl = ustr_len(name);
            o += sprintf_s(m + o, cap - o, ",\"c\":%u,\"n\":\"", color);
            b64enc(nl ? (const unsigned char *)name : (const unsigned char *)"", nl * 2, m + o);
            o += (int)strlen(m + o);
            m[o++] = '"'; m[o] = 0;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { free(m); return NULL; }
    sprintf_s(m + o, cap - o, "}}");
    return m;
}

static void do_metasnap(const QItem *it) {
    int t = it->unit, i = it->a;
    uint64_t h = meta_hash(t, i);
    if (!h || h == g_mHash[t][i]) return;
    char *m = meta_json(t, i);
    if (!m) return;
    ws_send(m);
    free(m);
    g_mHash[t][i] = h;
    g_mSentAt[t][i] = GetTickCount();
    logmsg("META sent %s %d", M_TAG[t], i);
}

// Poll thread: find entities that changed locally and settled.
static void scan_meta(DWORD now) {
    static DWORD last = 0;
    static int pend[M_NTYPES * META_MAX];
    int t, i, np = 0;
    if (now - last < META_SCAN_MS || g_patDepth) return;
    last = now;
    if (!g_metaReady) { meta_rebaseline(0); g_metaReady = 1; return; }
    meta_observe(now);
    for (t = 0; t < M_NTYPES; t++)
        for (i = 0; i < meta_cap(t); i++) {
            if (!g_mAt[t][i] || now - g_mAt[t][i] < META_SETTLE_MS) continue;
            g_mAt[t][i] = 0;
            if (g_mSeen[t][i] == g_mHash[t][i]) continue;
            if (!g_mSeen[t][i] || !g_mHash[t][i] ||   // gone / just appeared: structural sync handles it
                (t == M_CHAN && (g_chU[i].addAt || (LONG)(now - g_chU[i].absorbUntil) < 0))) {
                g_mHash[t][i] = g_mSeen[t][i];        // new / remotely loaded channel: its name came with its state
                continue;
            }
            pend[np++] = t * META_MAX + i;
        }
    if (np >= META_BULK) {
        for (i = 0; i < np; i++) g_mHash[pend[i] / META_MAX][pend[i] % META_MAX] = g_mSeen[pend[i] / META_MAX][pend[i] % META_MAX];
        logmsg("META bulk change in %d entities: not sent", np);
        return;
    }
    for (i = 0; i < np; i++) enqueue_unit(T_METASNAP, pend[i] / META_MAX, pend[i] % META_MAX, 0, 0, NULL);
}

// Inbound meta.set: the whole message goes to the main thread.
static void on_meta_set(const char *m) {
    QItem q; memset(&q, 0, sizeof(q));
    q.type = T_META; q.path = _strdup(m);
    enqueue(&q);
}

static wchar_t *meta_name_arg(const wchar_t *w) { return w[0] ? dstr_keep(w) : NULL; }   // '' = nil string

static int shared_int32(FlJson value, int *out) {
    uint64_t n; int negative = value.n && value.p[0] == '-';
    if (negative) { value.p++; value.n--; }
    if (!fc_uint(value, &n) || n > (negative ? 2147483648ull : 2147483647ull)) return 0;
    *out = negative ? (int)-(int64_t)n : (int)n;
    return 1;
}

static int shared_array_fields(FlJson array, FlJson *fields, int count) {
    const char *p = array.p, *end = p + array.n, *start;
    int n = 0;
    if (array.n < 2 || *p++ != '[' || end[-1] != ']') return 0;
    end--; fj_space(&p, end);
    while (p < end) {
        start = p;
        if (n == count || !fj_value(&p, end, 0)) return 0;
        fields[n].p = start; fields[n++].n = (size_t)(p - start);
        fj_space(&p, end);
        if (p < end) { if (*p++ != ',') return 0; fj_space(&p, end); if (p == end) return 0; }
    }
    return n == count;
}

typedef struct { int pos, action; unsigned char tail[MARK_SIZE - MARK_TAIL]; wchar_t *name; } IncomingMarker;

// Parse every marker and allocate its name before replacing the local list.
static int marks_apply(int t, int i, const char *m) {
    FlJson root = {m, strlen(m)}, op, markers;
    const char *p, *end, *start;
    IncomingMarker *parsed = NULL;
    char **list;
    void *ti;
    markadd_t add = (markadd_t)(g_flBase + (MARKADD_VA - IMG_BASE));
    int n = 0, k, applied = 0;
    if (!fj_get(root, "op", &op)) op = root;
    if (!fj_get(op, "mk", &markers) || markers.n < 2 || markers.p[0] != '[') goto invalid;
    parsed = (IncomingMarker *)calloc(MARK_MAX, sizeof(*parsed));
    if (!parsed) goto memory;
    p = markers.p + 1; end = markers.p + markers.n - 1; fj_space(&p, end);
    while (p < end) {
        FlJson item, fields[4], tail, name;
        size_t tn, nn; unsigned char *bytes; wchar_t wide[256];
        start = p;
        if (n == MARK_MAX || !fj_value(&p, end, 0)) goto invalid;
        item.p = start; item.n = (size_t)(p - start);
        if (!shared_array_fields(item, fields, 4) || !shared_int32(fields[0], &parsed[n].pos) ||
            !shared_int32(fields[1], &parsed[n].action) ||
            !shared_b64(fields[2], &tail, MARK_SIZE - MARK_TAIL, &tn) || tn != MARK_SIZE - MARK_TAIL ||
            !shared_b64(fields[3], &name, 510, &nn) || nn % 2) goto invalid;
        bytes = b64dec(tail.p, tail.n, &tn);
        if (!bytes) goto cleanup;
        memcpy(parsed[n].tail, bytes, tn); free(bytes);
        bytes = b64dec(name.p, name.n, &nn);
        if (!bytes) goto cleanup;
        memcpy(wide, bytes, nn); free(bytes); wide[nn / 2] = 0;
        if (wcslen(wide) != nn / 2) goto invalid;
        if (nn && !(parsed[n].name = dstr_keep(wide))) goto memory;
        n++;
        fj_space(&p, end);
        if (p < end) { if (*p++ != ',') goto invalid; fj_space(&p, end); }
    }
    list = marks_of(t, i);
    ti = *(void **)(g_flBase + (MARKTYPE_VA - IMG_BASE));
    EnterCriticalSection(song_lock());
    __try {
        __try {
            ((dynsetlen_t)(g_flBase + (DYNSETLEN_VA - IMG_BASE)))(list, ti, 1, 0);
            for (k = 0; k < n; k++) {
                IncomingMarker *marker = &parsed[k];
                wchar_t *name = marker->name;
                marker->name = NULL; // FL may retain this Delphi literal.
                add(list, marker->pos, name, marker->action, marker->tail[0], marker->tail[1]);
                if (mark_count(*list) != k + 1) __leave;
                memcpy(*list + (size_t)k * MARK_SIZE + MARK_TAIL, marker->tail, sizeof(marker->tail));
            }
            applied = k == n;
        } __except (EXCEPTION_EXECUTE_HANDLER) { applied = 0; }
    } __finally { LeaveCriticalSection(song_lock()); }
    if (!applied) {
        sharing_fail("Shared markers: session stopped", "FL Studio could not apply the shared markers. Check your local markers before reconnecting.");
        goto cleanup;
    }
    if (t == M_PMARK) {
        // what the piano roll's MarkersChanged does for its pattern, for any pattern
        ((formfn_t)(g_flBase + (MARKSORT_VA - IMG_BASE)))(list);
        ((patlenupd_t)(g_flBase + (PATLENUPD_VA - IMG_BASE)))(i, 0);
        ((formfn_t)(g_flBase + (PATMARKS_VA - IMG_BASE)))(pat_rec(i));
        playlist_refresh();                                          // pattern clips change length
    } else if (i == cur_arr()) {
        char *form = **(char ***)(g_flBase + (PLFORM_VA - IMG_BASE));
        if (form) {
            *(int32_t *)(form + PL_MARKSEL) = -1;
            ((formfn_t)(g_flBase + (MARKREFRESH_VA - IMG_BASE)))(form);
        }
    }
    ((setmod_t)(g_flBase + (MODIFIED_VA - IMG_BASE)))(1);
    goto cleanup;
invalid:
    sharing_fail("Shared markers: session stopped", "The shared marker list is incomplete or invalid. Your local markers were kept.");
    goto cleanup;
memory:
    sharing_fail("Shared markers: session stopped", "There is not enough memory to receive the shared marker list. Your local markers were kept.");
cleanup:
    if (parsed) for (k = 0; k < MARK_MAX; k++) dstr_free(parsed[k].name);
    free(parsed);
    return applied;
}

static int routes_parse(const char *m, unsigned char *on, int *levels) {
    FlJson root = {m, strlen(m)}, op, routes;
    const char *p, *end, *start;
    memset(on, 0, MIX_ROUTE_MAX);
    if (!fj_get(root, "op", &op)) op = root;
    if (!fj_get(op, "r", &routes) || routes.n < 2 || routes.p[0] != '[') return 0;
    p = routes.p + 1; end = routes.p + routes.n - 1; fj_space(&p, end);
    while (p < end) {
        FlJson item, fields[2]; uint64_t target; int level;
        start = p;
        if (!fj_value(&p, end, 0)) return 0;
        item.p = start; item.n = (size_t)(p - start);
        if (!shared_array_fields(item, fields, 2) || !fc_uint(fields[0], &target) ||
            target >= MIX_ROUTE_MAX || on[target] || !shared_int32(fields[1], &level)) return 0;
        on[target] = 1; levels[target] = level;
        fj_space(&p, end);
        if (p < end) { if (*p++ != ',') return 0; fj_space(&p, end); }
    }
    return 1;
}

// Project time signature: FL's setter reads the toolbar's time controls, so put the new values in
// the controls (from the globals), put the old globals back, and let the setter see the change.
static void tsig_apply(int nu, int de) {
    char *form = **(char ***)(g_flBase + (MAINFORM_VA - IMG_BASE));
    int *pn = ts_num(), *pd = ts_den(), on = *pn, od = *pd;
    if (!form || nu < 1 || nu > 16 || de < 1 || de > 16 || (nu == on && de == od)) return;
    *pn = nu; *pd = de;
    ((formfn_t)(g_flBase + (TSCTLS_VA - IMG_BASE)))(form);
    *pn = on; *pd = od;
    ((formfn_t)(g_flBase + (TSSET_VA - IMG_BASE)))(form);
    if (*pn != nu || *pd != de) logmsg("META time signature %d/%d came out as %d/%d", nu, de, *pn, *pd);
}

static void do_meta(const QItem *it) {
    const char *m = it->path;
    FlJson root = {m, strlen(m)}, op, value, data;
    char tag[8];
    int t, i = -1, len = 0, hasL = 0, hasC = 0, faulted = 0, nu = 0, de = 0;
    uint32_t color = 0;
    wchar_t *name = NULL;
    DWORD now = GetTickCount();
    if (!fj_get(root, "op", &op)) op = root;
    if (!fc_text(op, "e", tag, sizeof(tag)) || !fj_get(op, "i", &value) || !shared_int32(value, &i)) goto invalid;
    for (t = 0; t < M_NTYPES && strcmp(tag, M_TAG[t]); t++) {}
    if (t == M_NTYPES || !meta_valid(t, i)) goto invalid;
    if (fj_get(op, "n", &value)) {
        unsigned char *decoded; size_t bytes, j;
        if (!shared_b64(value, &data, 8192, &bytes) || bytes % 2) goto invalid;
        decoded = b64dec(data.p, data.n, &bytes);
        if (!decoded) return;
        name = (wchar_t *)calloc(bytes / 2 + 1, sizeof(wchar_t));
        if (!name) { free(decoded); goto invalid; }
        memcpy(name, decoded, bytes); free(decoded);
        for (j = 0; j < bytes / 2; j++) {
            unsigned c = name[j];
            if (!c || (c >= 0xdc00 && c <= 0xdfff)) goto invalid;
            if (c >= 0xd800 && c <= 0xdbff && (++j >= bytes / 2 || name[j] < 0xdc00 || name[j] > 0xdfff)) goto invalid;
        }
    }
    if (fj_get(op, "c", &value)) { if (!fj_u32(value, &color)) goto invalid; hasC = 1; }
    if (fj_get(op, "l", &value)) { if (!shared_int32(value, &len)) goto invalid; hasL = 1; }
    if (t == M_TSIG && (!fj_get(op, "nu", &value) || !shared_int32(value, &nu) || nu < 1 || nu > 16 ||
        !fj_get(op, "de", &value) || !shared_int32(value, &de) || de < 1 || de > 16)) goto invalid;
    if (g_isLeader && g_mSentAt[t][i] && now - g_mSentAt[t][i] < META_CONFLICT_MS) {
        // both changed it at once: the leader's value wins; send ours again so the peer converges
        g_mHash[t][i] = 0;
        enqueue_unit(T_METASNAP, t, i, 0, 0, NULL);
        logmsg("META %s %d: changed here too, keeping ours", M_TAG[t], i);
        free(name);
        return;
    }
    meta_observe(now); // Preserve local edits that arrived before the next scanner tick.
    __try {
        switch (t) {
        case M_MIX: {
            char *r = mix_rec(i);
            if (name && !ustr_eq(*(wchar_t **)(r + MIX_NAME), name))
                ((mixname_t)(g_flBase + (MIXNAME_VA - IMG_BASE)))(i, meta_name_arg(name), 1);
            if (hasC && *(uint32_t *)(r + MIX_COLOR) != color) {
                ((mixcolor_t)(g_flBase + (MIXCOLOR_VA - IMG_BASE)))(r, color);
                ((uiupdate_t)(g_flBase + (UIUPDATE_VA - IMG_BASE)))(0x18, 0);
            }
            break; }
        case M_ROUTE: {
            static unsigned char on[MIX_ROUTE_MAX];
            static int lvl[MIX_ROUTE_MAX];
            char *r = mix_rec(i);
            void *mixer = **(void ***)(g_flBase + (MIXOBJ_VA - IMG_BASE));
            int d, nm = mix_count(), changed = 0;
            if (!routes_parse(m, on, lvl)) {
                sharing_fail("Shared routing: session stopped", "The shared mixer routing is incomplete or invalid. Your local routes were kept.");
                free(name); return;
            }
            if (!mixer) break;
            for (d = 0; d < nm && d < MIX_ROUTE_MAX; d++) {
                int cur = r[MIX_ROUTE + d * 8 + 4] != 0;
                if (cur != on[d]) { ((setroute_t)(g_flBase + (SETROUTE_VA - IMG_BASE)))(mixer, i, d, on[d], 1); changed = 1; }
                if (on[d] && *(int32_t *)(r + MIX_ROUTE + d * 8) != lvl[d]) { *(int32_t *)(r + MIX_ROUTE + d * 8) = lvl[d]; changed = 1; }
            }
            if (changed) {
                ((mixerfn_t)(g_flBase + (ROUTEUPD_VA - IMG_BASE)))(mixer);
                ((uiupdate_t)(g_flBase + (UIUPDATE_VA - IMG_BASE)))(0x18, 0);
            }
            break; }
        case M_CHAN: {
            char *o = (char *)chan_obj(i);
            void **vmt;
            if (!o) break;
            vmt = *(void ***)o;
            if (name && !ustr_eq(*(wchar_t **)(o + CH_NAME), name)) ((chsetname_t)vmt[CH_SETNAME_VSLOT])(o, meta_name_arg(name));
            if (hasC && *(uint32_t *)(o + CH_COLOR) != color) ((chsetcolor_t)vmt[CH_SETCOLOR_VSLOT])(o, color);
            break; }
        case M_PAT: {
            char *r = pat_rec(i);
            int changed = 0;
            if (name && !ustr_eq(*(wchar_t **)(r + PAT_NAME), name)) { ((patname_t)(g_flBase + (PATNAME_VA - IMG_BASE)))(i, meta_name_arg(name)); changed = 1; }
            if (hasC && *(uint32_t *)(r + PAT_COLOR) != color) { ((patcolor_t)(g_flBase + (PATCOLOR_VA - IMG_BASE)))(i, color); changed = 1; }
            if (hasL && *(int32_t *)(r + PAT_LENGTH) != len) { *(int32_t *)(r + PAT_LENGTH) = len; changed = 1; }
            if (changed) {
                char *form = **(char ***)(g_flBase + (PLFORM_VA - IMG_BASE));
                void *pats = form ? *(void **)(form + PLFORM_PATS) : NULL;
                if (pats) ((patrefresh_t)(g_flBase + (PATREFRESH_VA - IMG_BASE)))(pats, 1, 0);
                playlist_refresh();
            }
            break; }
        case M_PLT: {
            char *r = pl_track(i);
            if (!r) break;
            if ((name && !ustr_eq(*(wchar_t **)(r + PL_TRK_NAME), name)) || (hasC && *(uint32_t *)(r + PL_TRK_COLOR) != color))
                ((pltrack_t)(g_flBase + (PLTRACK_VA - IMG_BASE)))(arr_obj(i / 512), i % 512,
                    name ? meta_name_arg(name) : *(wchar_t **)(r + PL_TRK_NAME),
                    hasC ? color : *(uint32_t *)(r + PL_TRK_COLOR));
            break; }
        case M_MARK: case M_PMARK:
            if (!marks_apply(t, i, m)) { free(name); return; }
            break;
        case M_TSIG: {
            tsig_apply(nu, de);
            break; }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { faulted = 1; logmsg("META apply faulted %s %d", M_TAG[t], i); }
    free(name);
    if (faulted) { sharing_fail("Shared details: sharing paused", "FL could not apply the shared project details. Reconnect and resync before continuing."); return; }
    g_mSeen[t][i] = g_mHash[t][i] = meta_hash(t, i);
    g_mAt[t][i] = 0;
    meta_absorb();
    logmsg("META applied %s %d", M_TAG[t], i);
    return;
invalid:
    free(name);
    sharing_fail("Shared details: sharing paused", "The shared name, color, length or time signature is invalid. Your local details were kept.");
}

// ---------------- window guard ----------------
// Window state is client-only: what is open, where, and in which order is never
// synced. FL's preset loader opens/raises the plugin editor, so around every
// remote-originated heavy op we snapshot FL's floating forms and put things back
// afterwards (and keep doing so for a moment, as FL shows some windows late).
// Local input during that time ends the guard: the user's own actions win.
#define WG_MAX       128
#define WG_GUARD_MS  2000
typedef struct { HWND h; RECT r; int plugin; } WinRec;
typedef struct { int n; WinRec w[WG_MAX]; HWND fg, focus; DWORD at; } WinSnap;
static WinSnap g_wsnap;
static DWORD   g_wguardUntil = 0, g_wguardLast = 0;
static HWND    g_mainForm = NULL;

static int wnd_class_is(HWND h, const char *cls) {
    char c[64]; GetClassNameA(h, c, sizeof(c)); return strcmp(c, cls) == 0;
}
// FL's floating forms (plugin wrappers, channel rack, mixer, playlist, browser...)
static int is_fl_form(HWND h) {
    char c[64]; size_t n;
    GetClassNameA(h, c, sizeof(c)); n = strlen(c);
    return n > 5 && c[0] == 'T' && strcmp(c + n - 4, "Form") == 0 && strcmp(c, "TFruityLoopsMainForm") != 0;
}
static void rect_in_parent(HWND h, RECT *r) {
    GetWindowRect(h, r);
    MapWindowPoints(NULL, GetParent(h), (POINT *)r, 2);
}

typedef struct { HWND list[WG_MAX]; int n; } HwndList;
static BOOL CALLBACK collect_forms(HWND h, LPARAM lp) {
    HwndList *L = (HwndList *)lp;
    if (L->n < WG_MAX && IsWindowVisible(h) && is_fl_form(h)) L->list[L->n++] = h;
    return TRUE;
}
// visible FL forms, topmost first (EnumChildWindows walks siblings in z-order)
static void visible_forms(HwndList *L) {
    L->n = 0;
    if (g_mainForm) EnumChildWindows(g_mainForm, collect_forms, (LPARAM)L);
}

static BOOL CALLBACK redraw_cb(HWND h, LPARAM lp) {
    (void)lp;
    if (wnd_class_is(h, "TEventEditForm")) RedrawWindow(h, NULL, NULL, RDW_INVALIDATE | RDW_ALLCHILDREN);
    return TRUE;
}
static void redraw_editors(void) {
    if (g_mainForm) EnumChildWindows(g_mainForm, redraw_cb, 0);
}

static void wguard_begin(void) {
    DWORD now = GetTickCount();
    if (now < g_wguardUntil) { g_wguardUntil = now + WG_GUARD_MS; return; }   // extend, keep first snapshot
    HwndList L; int i;
    visible_forms(&L);
    g_wsnap.n = L.n;
    for (i = 0; i < L.n; i++) {
        g_wsnap.w[i].h = L.list[i];
        g_wsnap.w[i].plugin = wnd_class_is(L.list[i], "TPluginForm");
        rect_in_parent(L.list[i], &g_wsnap.w[i].r);
    }
    g_wsnap.fg = GetForegroundWindow();
    g_wsnap.focus = GetFocus();
    g_wsnap.at = now;
    g_wguardUntil = now + WG_GUARD_MS;
}

static int snap_index(HWND h) {
    int i;
    for (i = 0; i < g_wsnap.n; i++) if (g_wsnap.w[i].h == h) return i;
    return -1;
}

static void wguard_pass(void) {
    DWORD now = GetTickCount();
    HwndList L; int i, j, changedOrder = 0;
    if (!g_wguardUntil || now >= g_wguardUntil) { g_wguardUntil = 0; return; }
    if (g_lastInput && (LONG)(g_lastInput - g_wsnap.at) > 0) { g_wguardUntil = 0; return; }  // user took over
    visible_forms(&L);
    // windows that newly appeared: a replaced plugin's editor takes over its old
    // window's place; anything else the remote op opened gets closed again
    for (i = 0; i < L.n; i++) {
        HWND h = L.list[i];
        if (snap_index(h) >= 0 || !wnd_class_is(h, "TPluginForm")) continue;
        int heir = -1;
        for (j = 0; j < g_wsnap.n; j++)
            if (g_wsnap.w[j].plugin && (!IsWindow(g_wsnap.w[j].h) || !IsWindowVisible(g_wsnap.w[j].h))) { heir = j; break; }
        if (heir >= 0) {
            RECT r = g_wsnap.w[heir].r;
            SetWindowPos(h, NULL, r.left, r.top, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
            g_wsnap.w[heir].h = h;            // it now stands in for the old one
            logmsg("WINDOW kept replaced plugin editor in place");
        } else {
            SendMessageW(h, WM_CLOSE, 0, 0);  // same as the user closing it
            logmsg("WINDOW closed editor opened by a remote op");
        }
    }
    // positions
    for (i = 0; i < g_wsnap.n; i++) {
        HWND h = g_wsnap.w[i].h; RECT r;
        if (!IsWindow(h) || !IsWindowVisible(h)) continue;
        rect_in_parent(h, &r);
        if (r.left != g_wsnap.w[i].r.left || r.top != g_wsnap.w[i].r.top)
            SetWindowPos(h, NULL, g_wsnap.w[i].r.left, g_wsnap.w[i].r.top, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    }
    // stacking order: compare current order of the snapshot windows with the snapshot
    visible_forms(&L);
    {
        int k = 0;
        for (i = 0; i < L.n; i++) {
            int si = snap_index(L.list[i]);
            if (si < 0) continue;
            while (k < g_wsnap.n && !IsWindowVisible(g_wsnap.w[k].h)) k++;
            if (k >= g_wsnap.n || g_wsnap.w[k].h != L.list[i]) { changedOrder = 1; break; }
            k++;
        }
    }
    if (changedOrder) {
        for (i = g_wsnap.n - 1; i >= 0; i--)          // bottom-most first, so the old top ends on top
            if (IsWindow(g_wsnap.w[i].h) && IsWindowVisible(g_wsnap.w[i].h))
                SetWindowPos(g_wsnap.w[i].h, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        logmsg("WINDOW restored stacking order");
    }
    if (g_wsnap.fg && GetForegroundWindow() != g_wsnap.fg && IsWindow(g_wsnap.fg)) SetForegroundWindow(g_wsnap.fg);
    if (g_wsnap.focus && GetFocus() != g_wsnap.focus && IsWindow(g_wsnap.focus)) SetFocus(g_wsnap.focus);
    g_wguardLast = now;
}

// Room connections are managed by the desktop app; FL's toolbar only shows status.
enum { NET_OFF, NET_CONNECTING, NET_ON, NET_ERR };
#define WM_FLIM_STATUS  (WM_APP + 0x31)
#define WM_FLIM_HOSTED  (WM_APP + 0x32)    // user requested the session link
#define WM_FLIM_ALERT   (WM_APP + 0x33)    // net thread: show a passive hint
#define BAR_H_REF       26         // bar height at FL's 41 px toolbar row; sizes below scale with it
static HWND     g_netBar = NULL, g_netRow = NULL;
static int      g_badgeEnd = 0;
static int      g_barShowVersion = 1;
static HWND     g_tip = NULL;      // tooltip over the timer
static RECT     g_timerRc;         // where the timer was drawn (empty = none)

// Public sessions end after 15 minutes (server); whoever was in one then waits 5 minutes before
// hosting / joining another public one. Both counted down at the right end of the bar.
#define LIMIT_TEXT  "To avoid hogging, sessions are limited to 15 minutes for testing. " \
                    "You will keep all progress on your client when time runs out."
#define LIMIT_TEXTW L"To avoid hogging, sessions are limited to 15 minutes for testing. " \
                    L"You will keep all progress on your client when time runs out."
static volatile ULONGLONG g_endsAt = 0;      // GetTickCount64 when our session ends (0 = no limit)
static volatile ULONGLONG g_coolUntil = 0;   // GetTickCount64 when our cooldown ends
static HFONT    g_verFont = NULL;
static int      g_verFontH = 0;
static HICON    g_bean = NULL;
#define BEAN_SZ(h) ((h) * 4 / 3)
static int      g_beanSz = 0;
static COLORREF g_toolbarBg = RGB(0x4b, 0x55, 0x5c);
static HFONT    g_barFont = NULL;
static int      g_barFontH = 0;
static volatile LONG g_uiWanted = 0;
static volatile LONG g_netState = NET_OFF;
static CRITICAL_SECTION g_netTextLock;
static wchar_t  g_netText[256] = L"Not connected";
static char     g_myName[96];      // UTF-8, sanitized

static void net_connect(const char *url, const char *pw, int host, const char *owner);
static void samples_key(const char *hex);
static void peer_welcome(const char *message);
static void net_disconnect(void);
static void focus_summary(char *out, int cap, const char *sep);
static void json_esc(const char *in, char *out, int cap);
static void fl_hint(const char *msg);
static void cursor_update(void);
#define CUR_TIMER     2            // net bar timer: other people's mouse arrows
#define CUR_TIMER_MS  40

// Any thread: set the status text (UTF-8) and repaint the bar.
static void net_status(int state, const char *fmt, ...) {
    char a[256];
    va_list ap; va_start(ap, fmt); _vsnprintf_s(a, sizeof(a), _TRUNCATE, fmt, ap); va_end(ap);
    EnterCriticalSection(&g_netTextLock);
    MultiByteToWideChar(CP_UTF8, 0, a, -1, g_netText, 256);
    LeaveCriticalSection(&g_netTextLock);
    InterlockedExchange(&g_netState, state);
    logmsg("NET %s", a);
    if (g_netBar) PostMessageW(g_netBar, WM_FLIM_STATUS, 0, 0);
}

static char g_netShown[300];       // the server as shown in the status ("host[:port]", then "host[:port]/NN")
static char g_netRoot[300];        // the server alone ("host[:port]")
static NetUrl g_netUrl;            // the server of the current connection
static char g_netErr[160];         // why the server ended the current connection, if it said so
static char g_session[FLIM_SESSION_CAP]; // legacy slot or desktop room code once welcomed
static char g_hostPw[256];         // hosting: the session password, until the welcome
static char g_hostedText[700];     // hosting: session + link + password, for the "you're hosting" dialog
static char g_alert[400];          // message box text (g_netTextLock)
static int  g_alertInfo;           // ... shown as information, not a warning
static volatile LONG g_hosting = 0;  // this connection hosts (vs joins)

// Any thread: a message box on FL's main thread.
static void net_alert_v(int info, const char *fmt, va_list ap) {
    EnterCriticalSection(&g_netTextLock);
    vsprintf_s(g_alert, sizeof(g_alert), fmt, ap);
    g_alertInfo = info;
    LeaveCriticalSection(&g_netTextLock);
    if (g_netBar) PostMessageW(g_netBar, WM_FLIM_ALERT, 0, 0);
}
static void net_alert(const char *fmt, ...) { va_list ap; va_start(ap, fmt); net_alert_v(0, fmt, ap); va_end(ap); }
static void net_info(const char *fmt, ...) { va_list ap; va_start(ap, fmt); net_alert_v(1, fmt, ap); va_end(ap); }

// The bar's timer: time left in a timed session, else a running cooldown. 0 = nothing to show.
static int bar_timer_text(wchar_t *out, int cap, int *cool, int *last) {
    ULONGLONG now = GetTickCount64(), end = g_endsAt, cu = g_coolUntil, left;
    unsigned s;
    *cool = *last = 0;
    if (g_netState == NET_ON && end) left = end > now ? end - now : 0;
    else if (cu > now) { left = cu - now; *cool = 1; }
    else { out[0] = 0; return 0; }
    s = (unsigned)((left + 999) / 1000);
    *last = s <= 60;
    swprintf_s(out, cap, L"%s %02u:%02u", *cool ? L"COOLDOWN:" : L"TIME LEFT:", s / 60, s % 60);
    return 1;
}
static unsigned cooldown_secs(void) {
    ULONGLONG now = GetTickCount64(), cu = g_coolUntil;
    return cu > now ? (unsigned)((cu - now + 999) / 1000) : 0;
}

// welcome / presence: "Connected to <server> · leader · 3 people"
static void net_show_connected(const char *m) {
    const char *p = strstr(m, "\"peers\":[");
    int n = 0;
    while (p && (p = strstr(p + 1, "\"role\":\"")) != NULL) n++;
    char where[600];
    focus_summary(where, sizeof(where), " \xC2\xB7 ");
    net_status(NET_ON, "Connected to %s \xC2\xB7 %s \xC2\xB7 %d %s%s%s", g_netShown, g_isLeader ? "leader" : "member",
               n, n == 1 ? "person" : "people", where[0] ? " \xC2\xB7 " : "", where);
}

static void plugins_changed(void) {
    int i, n = 0, retryable = 0;
    for (i = 0; i < MAX_CH; i++) if (g_chU[i].unavailable) { n++; retryable += g_chU[i].unavailable == 1; }
    for (i = 0; i < MAX_MIX * MAX_FX_SLOTS; i++) { LONG unavailable = g_fxU[i / MAX_FX_SLOTS][i % MAX_FX_SLOTS].unavailable; if (unavailable) { n++; retryable += unavailable == 1; } }
    InterlockedExchange(&g_pluginMissing, n);
    InterlockedExchange(&g_pluginRetryable, retryable);
    if (g_netBar) PostMessageW(g_netBar, WM_FLIM_STATUS, 0, 0);
}

static void plugins_dialog(HWND h) {
    (void)h;
    if (g_pluginMissing) fl_hint("Unavailable sounds are retained. Notes and shared controls continue. Matching scanned plugins recover automatically; details are in the log.");
}

static void bar_paint(HWND h) {
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(h, &ps);
    RECT rc; GetClientRect(h, &rc);
    int W = rc.right, H = rc.bottom, st = g_netState;
    HDC mem = CreateCompatibleDC(dc);
    HBITMAP bmp = CreateCompatibleBitmap(dc, W, H);
    HGDIOBJ oldBmp = SelectObject(mem, bmp), oldFont;
    HBRUSH bg = CreateSolidBrush(g_toolbarBg);
    FillRect(mem, &rc, bg); DeleteObject(bg);
    if (!g_barFont || g_barFontH != H) {
        if (g_barFont) DeleteObject(g_barFont);
        g_barFontH = H;
        g_barFont = CreateFontW(-(H * 14 / BAR_H_REF), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    }
    if (!g_verFont || g_verFontH != H) {
        if (g_verFont) DeleteObject(g_verFont);
        g_verFontH = H;
        g_verFont = CreateFontW(-(H * 12 / BAR_H_REF), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    }
    SetBkMode(mem, TRANSPARENT);
    {   // badge: the bean + "flim v.YY.MM.DD" in small gray text
        RECT vr;
        int S = BEAN_SZ(H);                 // the bean is wide: its square icon is drawn taller than the bar
        if (!g_bean || g_beanSz != S) {
            if (g_bean) DestroyIcon(g_bean);
            g_beanSz = S;
            g_bean = (HICON)LoadImageW(g_hinst, MAKEINTRESOURCEW(IDI_BEAN), IMAGE_ICON, S, S, 0);
        }
        if (g_bean) DrawIconEx(mem, 0, (H - S) / 2, g_bean, S, S, 0, NULL, DI_NORMAL);
        oldFont = SelectObject(mem, g_verFont);
        SetTextColor(mem, RGB(0xd4, 0xda, 0xde));
        SetRect(&vr, S + H / 8, 0, g_badgeEnd, H);
        if (g_barShowVersion) DrawTextW(mem, L"flim v." FLIM_VERSION_W, -1, &vr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        SelectObject(mem, g_barFont);
    }
    {   // status dot + text
        COLORREF dot = st == NET_ON ? RGB(0x5c, 0xd6, 0x6b) : st == NET_CONNECTING ? RGB(0xf2, 0xb7, 0x3a)
                     : st == NET_ERR ? RGB(0xf0, 0x6a, 0x5f) : RGB(0x8d, 0x97, 0x9e);
        int d = H * 8 / BAR_H_REF, x = g_badgeEnd + H / 2;
        HBRUSH db = CreateSolidBrush(dot);
        HGDIOBJ ob = SelectObject(mem, db), op = SelectObject(mem, GetStockObject(NULL_PEN));
        RECT tr;
        Ellipse(mem, x, (H - d) / 2, x + d + 1, (H - d) / 2 + d + 1);
        SelectObject(mem, ob); SelectObject(mem, op); DeleteObject(db);
        {   // timer at the right end (with a tooltip)
            wchar_t tt[48];
            int cool, last;
            RECT rr = { 0, 0, 0, 0 };
            if (bar_timer_text(tt, 48, &cool, &last)) {
                SIZE sz;
                GetTextExtentPoint32W(mem, tt, (int)wcslen(tt), &sz);
                SetRect(&rr, W - sz.cx - H / 4, 0, W - H / 4, H);
                SetTextColor(mem, cool ? RGB(0xf2, 0xb7, 0x3a) : last ? RGB(0xff, 0xa0, 0x96) : RGB(0xd4, 0xda, 0xde));
                DrawTextW(mem, tt, -1, &rr, DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            }
            if (!EqualRect(&rr, &g_timerRc)) {
                g_timerRc = rr;
                if (g_tip) {
                    TOOLINFOW ti; memset(&ti, 0, sizeof(ti));
                    ti.cbSize = TTTOOLINFOW_V2_SIZE; ti.hwnd = h; ti.uId = 1; ti.rect = rr;
                    SendMessageW(g_tip, TTM_NEWTOOLRECTW, 0, (LPARAM)&ti);
                }
            }
        }
        SetRect(&tr, x + d + H / 4, 0, g_timerRc.right ? g_timerRc.left - H / 2 : W, H);
        SetTextColor(mem, st == NET_ERR ? RGB(0xff, 0xa0, 0x96) : RGB(0xd4, 0xda, 0xde));
        EnterCriticalSection(&g_netTextLock);
        wchar_t status[320];
        if (g_pluginMissing) _snwprintf_s(status, 320, _TRUNCATE, L"%ld sound%s unavailable | %s", g_pluginMissing, g_pluginMissing == 1 ? L"" : L"s", g_netText);
        else wcscpy_s(status, 320, g_netText);
        DrawTextW(mem, status, -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        LeaveCriticalSection(&g_netTextLock);
        if (GetFocus() == h) DrawFocusRect(mem, &tr);
    }
    BitBlt(dc, 0, 0, W, H, mem, 0, 0, SRCCOPY);
    SelectObject(mem, oldFont); SelectObject(mem, oldBmp); DeleteObject(bmp); DeleteDC(mem);
    EndPaint(h, &ps);
}

// Fill the "Splitter_1" panel (FL's flexible gap) from just after the meters.
static void bar_layout(void) {
    RECT rr, sr, cur;
    HWND spl;
    int rowH, h, w, right, minX, x;
    if (!g_netBar || !IsWindow(g_netRow)) return;
    GetClientRect(g_netRow, &rr);
    rowH = rr.bottom > 0 ? rr.bottom : 41;
    h = rowH * BAR_H_REF / 41; if (h < 18) h = 18;
    {   // badge width = bean (h) + gap + version text + gap
        HDC dc = GetDC(g_netBar);
        HFONT f = CreateFontW(-(h * 12 / BAR_H_REF), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                              CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        HGDIOBJ of = SelectObject(dc, f);
        SIZE sz = { 0, 0 };
        GetTextExtentPoint32W(dc, L"flim v." FLIM_VERSION_W, (int)wcslen(L"flim v." FLIM_VERSION_W), &sz);
        SelectObject(dc, of); DeleteObject(f); ReleaseDC(g_netBar, dc);
        g_badgeEnd = BEAN_SZ(h) + h / 8 + sz.cx + h * 2 / 3;
    }
    right = rr.right - 8; minX = rr.right / 2;
    spl = FindWindowExW(g_netRow, NULL, L"TQuickEditToolbarPanel", L"Splitter_1");
    if (spl && IsWindowVisible(spl)) {
        GetWindowRect(spl, &sr);
        MapWindowPoints(NULL, g_netRow, (POINT *)&sr, 2);
        right = sr.right - 8;
        minX = sr.left + h / 4;
        {   // FL's own panels sit before it (meters: CPU / MB); never start on top of one that reaches in
            HWND c;
            for (c = GetWindow(g_netRow, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT)) {
                RECT cr;
                if (c == spl || c == g_netBar || !IsWindowVisible(c)) continue;
                GetWindowRect(c, &cr);
                MapWindowPoints(NULL, g_netRow, (POINT *)&cr, 2);
                if (cr.left < sr.left + (sr.right - sr.left) / 2 && cr.right > minX - h / 4 && cr.right < right)
                    minX = cr.right + h / 4;
            }
        }
    }
    // left-aligned right after FL's meters (CPU / MB), filling the gap: the status gets all the room
    // there is, the timer sits at the right end
    w = right - minX;
    if (w < h * 2) { ShowWindow(g_netBar, SW_HIDE); return; }
    g_barShowVersion = w >= g_badgeEnd + h * 6;
    if (!g_barShowVersion) g_badgeEnd = BEAN_SZ(h) + h / 4;
    if (!IsWindowVisible(g_netBar)) ShowWindow(g_netBar, SW_SHOWNOACTIVATE);
    x = minX;
    GetWindowRect(g_netBar, &cur);
    MapWindowPoints(NULL, g_netRow, (POINT *)&cur, 2);
    if (cur.left != x || cur.right - cur.left != w || cur.bottom - cur.top != h) {
        SetWindowPos(g_netBar, HWND_TOP, x, (rowH - h) / 2, w, h, SWP_NOACTIVATE);
        InvalidateRect(g_netBar, NULL, FALSE);
    }
}

// ---- connect / host dialogs ----
static char g_dlgUrl[512], g_dlgPw[256], g_dlgOwner[256];
static int  g_dlgOwnerMode;

static void dlg_init_name(HWND dlg) {
    wchar_t v[512];
    MultiByteToWideChar(CP_UTF8, 0, g_myName, -1, v, 512);
    SetDlgItemTextW(dlg, IDC_CNAME, v);
    SendDlgItemMessageW(dlg, IDC_CNAME, EM_LIMITTEXT, 64, 0);
}

// The name from IDC_CNAME: 0 = not usable (the user was told).
static int dlg_take_name(HWND dlg) {
    wchar_t w[512], name[FLIM_NAME_MAX + 1];
    char n8[sizeof(g_myName)];
    GetDlgItemTextW(dlg, IDC_CNAME, w, 512);
    if (!flim_sanitize_name(w, name, FLIM_NAME_MAX + 1)) {
        MessageBoxW(dlg, L"Enter a name with at least one letter or digit.", L"flim", MB_OK | MB_ICONWARNING);
        SetFocus(GetDlgItem(dlg, IDC_CNAME));
        return 0;
    }
    // save the name only when it was edited here (FLIM_NAME dev overrides stay out of flim.ini)
    WideCharToMultiByte(CP_UTF8, 0, name, -1, n8, sizeof(n8), NULL, NULL);
    if (strcmp(n8, g_myName) != 0) { strcpy_s(g_myName, sizeof(g_myName), n8); flimcfg_set(L"name", name); }
    return 1;
}

// Text of a dialog control as UTF-8.
static void dlg_text8(HWND dlg, int id, char *out, int cap) {
    wchar_t w[512];
    GetDlgItemTextW(dlg, id, w, 512);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, cap, NULL, NULL);
    SecureZeroMemory(w, sizeof(w));
}

static INT_PTR CALLBACK connect_proc(HWND dlg, UINT m, WPARAM wp, LPARAM lp) {
    (void)lp;
    if (m == WM_INITDIALOG) {
        wchar_t v[512], rem[8];
        flimcfg_get(L"join_link", v, 512);
        SetDlgItemTextW(dlg, IDC_URL, v);
        flimcfg_get_secret(L"join_pw", g_dlgPw, sizeof(g_dlgPw));
        MultiByteToWideChar(CP_UTF8, 0, g_dlgPw, -1, v, 512);
        SetDlgItemTextW(dlg, IDC_PASSWORD, v);
        SecureZeroMemory(g_dlgPw, sizeof(g_dlgPw)); SecureZeroMemory(v, sizeof(v));
        flimcfg_get(L"remember_pw", rem, 8);
        CheckDlgButton(dlg, IDC_REMEMBER, rem[0] == L'0' ? BST_UNCHECKED : BST_CHECKED);
        dlg_init_name(dlg);
        SetFocus(GetDlgItem(dlg, GetWindowTextLengthW(GetDlgItem(dlg, IDC_URL)) ? IDOK : IDC_URL));
        return FALSE;
    }
    if (m == WM_COMMAND && LOWORD(wp) == IDOK) {
        wchar_t w[512];
        NetUrl u;
        char sess[FLIM_SESSION_CAP];
        int remember = IsDlgButtonChecked(dlg, IDC_REMEMBER) == BST_CHECKED;
        dlg_text8(dlg, IDC_URL, g_dlgUrl, sizeof(g_dlgUrl));
        if (!parse_link(g_dlgUrl, &u, sess)) {
            MessageBoxW(dlg, L"That doesn't look like a session link.\n\n"
                        L"It's the server with the session number, as the host got it, e.g.\n"
                        L"  https://flim.fly.dev/03", L"flim", MB_OK | MB_ICONWARNING);
            SetFocus(GetDlgItem(dlg, IDC_URL));
            return TRUE;
        }
        if (!GetWindowTextLengthW(GetDlgItem(dlg, IDC_PASSWORD))) {
            MessageBoxW(dlg, L"Enter the session password (the host has it).", L"flim", MB_OK | MB_ICONWARNING);
            SetFocus(GetDlgItem(dlg, IDC_PASSWORD));
            return TRUE;
        }
        if (!dlg_take_name(dlg)) return TRUE;
        dlg_text8(dlg, IDC_PASSWORD, g_dlgPw, sizeof(g_dlgPw));
        GetDlgItemTextW(dlg, IDC_URL, w, 512);
        flimcfg_set(L"join_link", w);
        flimcfg_set(L"remember_pw", remember ? L"1" : L"0");
        flimcfg_set_secret(L"join_pw", remember ? g_dlgPw : NULL);
        EndDialog(dlg, IDOK);
        return TRUE;
    }
    if (m == WM_COMMAND && LOWORD(wp) == IDCANCEL) { EndDialog(dlg, IDCANCEL); return TRUE; }
    return FALSE;
}

// A password suggestion for the host (they can type their own).
static void random_pw(wchar_t *out, int n) {
    static const char a[] = "abcdefghjkmnpqrstuvwxyz23456789";
    unsigned char r[16];
    int i;
    BCryptGenRandom(NULL, r, sizeof(r), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    for (i = 0; i < n && i < (int)sizeof(r); i++) out[i] = (wchar_t)a[r[i] % (sizeof(a) - 1)];
    out[i] = 0;
}

// lp = 1: owner mode (Ctrl+click), also asks for the owner key = session 00.
static INT_PTR CALLBACK host_proc(HWND dlg, UINT m, WPARAM wp, LPARAM lp) {
    if (m == WM_INITDIALOG) {
        wchar_t v[512];
        g_dlgOwnerMode = (int)lp;
        flimcfg_get(L"host_server", v, 512);
        SetDlgItemTextW(dlg, IDC_HSERVER, v[0] ? v : L"flim.fly.dev");
        random_pw(v, 8);
        SetDlgItemTextW(dlg, IDC_HPASSWORD, v);
        SendDlgItemMessageW(dlg, IDC_HPASSWORD, EM_LIMITTEXT, 128, 0);
        dlg_init_name(dlg);
        if (g_dlgOwnerMode) {
            ShowWindow(GetDlgItem(dlg, IDC_HOWNERLBL), SW_SHOW);
            ShowWindow(GetDlgItem(dlg, IDC_HOWNER), SW_SHOW);
            flimcfg_get_secret(L"owner_key", g_dlgOwner, sizeof(g_dlgOwner));
            if (!g_dlgOwner[0]) flimcfg_get_secret(L"server_pw", g_dlgOwner, sizeof(g_dlgOwner));  // the old server password
            MultiByteToWideChar(CP_UTF8, 0, g_dlgOwner, -1, v, 512);
            SetDlgItemTextW(dlg, IDC_HOWNER, v);
            SecureZeroMemory(g_dlgOwner, sizeof(g_dlgOwner)); SecureZeroMemory(v, sizeof(v));
            SetWindowTextW(dlg, L"flim - host with the owner key");
        } else {   // no owner row: move the buttons up into its place
            RECT lbl, btn, wr;
            int i, dy;
            GetWindowRect(GetDlgItem(dlg, IDC_HOWNERLBL), &lbl);
            GetWindowRect(GetDlgItem(dlg, IDOK), &btn);
            dy = btn.top - lbl.top;
            for (i = 0; i < 2; i++) {
                HWND b = GetDlgItem(dlg, i ? IDCANCEL : IDOK);
                RECT r; GetWindowRect(b, &r);
                MapWindowPoints(NULL, dlg, (POINT *)&r, 2);
                SetWindowPos(b, NULL, r.left, r.top - dy, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
            }
            GetWindowRect(dlg, &wr);
            SetWindowPos(dlg, NULL, 0, 0, wr.right - wr.left, wr.bottom - wr.top - dy, SWP_NOMOVE | SWP_NOZORDER);
        }
        SetFocus(GetDlgItem(dlg, IDC_HPASSWORD));
        SendDlgItemMessageW(dlg, IDC_HPASSWORD, EM_SETSEL, 0, -1);
        return FALSE;
    }
    if (m == WM_COMMAND && LOWORD(wp) == IDOK) {
        wchar_t w[512];
        NetUrl u;
        dlg_text8(dlg, IDC_HSERVER, g_dlgUrl, sizeof(g_dlgUrl));
        if (!parse_host(g_dlgUrl, &u)) {
            MessageBoxW(dlg, L"That doesn't look like a server address.\n\nExamples:\n  flim.fly.dev\n  localhost:8080",
                        L"flim", MB_OK | MB_ICONWARNING);
            SetFocus(GetDlgItem(dlg, IDC_HSERVER));
            return TRUE;
        }
        if (!GetWindowTextLengthW(GetDlgItem(dlg, IDC_HPASSWORD))) {
            MessageBoxW(dlg, L"Pick a session password.", L"flim", MB_OK | MB_ICONWARNING);
            SetFocus(GetDlgItem(dlg, IDC_HPASSWORD));
            return TRUE;
        }
        if (g_dlgOwnerMode && !GetWindowTextLengthW(GetDlgItem(dlg, IDC_HOWNER))) {
            MessageBoxW(dlg, L"Enter the owner key.", L"flim", MB_OK | MB_ICONWARNING);
            SetFocus(GetDlgItem(dlg, IDC_HOWNER));
            return TRUE;
        }
        if (!dlg_take_name(dlg)) return TRUE;
        dlg_text8(dlg, IDC_HPASSWORD, g_dlgPw, sizeof(g_dlgPw));
        g_dlgOwner[0] = 0;
        if (g_dlgOwnerMode) {
            dlg_text8(dlg, IDC_HOWNER, g_dlgOwner, sizeof(g_dlgOwner));
            flimcfg_set_secret(L"owner_key", g_dlgOwner);
        }
        GetDlgItemTextW(dlg, IDC_HSERVER, w, 512);
        flimcfg_set(L"host_server", w);
        EndDialog(dlg, IDOK);
        return TRUE;
    }
    if (m == WM_COMMAND && LOWORD(wp) == IDCANCEL) { EndDialog(dlg, IDCANCEL); return TRUE; }
    return FALSE;
}

// "You're hosting": session, link and password, with a Copy button.
static INT_PTR CALLBACK hosted_proc(HWND dlg, UINT m, WPARAM wp, LPARAM lp) {
    (void)lp;
    if (m == WM_INITDIALOG) {
        wchar_t w[700];
        EnterCriticalSection(&g_netTextLock);
        MultiByteToWideChar(CP_UTF8, 0, g_hostedText, -1, w, 700);
        LeaveCriticalSection(&g_netTextLock);
        SetDlgItemTextW(dlg, IDC_HINFO, w);
        SecureZeroMemory(w, sizeof(w));
        SetDlgItemTextW(dlg, IDC_HNOTE, g_endsAt ? LIMIT_TEXTW : L"");
        SetFocus(GetDlgItem(dlg, IDOK));
        return FALSE;
    }
    if (m == WM_COMMAND && LOWORD(wp) == IDC_HCOPY) {
        wchar_t w[700];
        int n = GetDlgItemTextW(dlg, IDC_HINFO, w, 700);
        if (OpenClipboard(dlg)) {
            HGLOBAL g = GlobalAlloc(GMEM_MOVEABLE, (n + 1) * sizeof(wchar_t));
            EmptyClipboard();
            if (g) {
                memcpy(GlobalLock(g), w, (n + 1) * sizeof(wchar_t));
                GlobalUnlock(g);
                if (!SetClipboardData(CF_UNICODETEXT, g)) GlobalFree(g);
            }
            CloseClipboard();
            SetDlgItemTextW(dlg, IDC_HCOPY, L"Copied");
        }
        SecureZeroMemory(w, sizeof(w));
        return TRUE;
    }
    if (m == WM_COMMAND && (LOWORD(wp) == IDOK || LOWORD(wp) == IDCANCEL)) { EndDialog(dlg, IDOK); return TRUE; }
    return FALSE;
}

static LRESULT CALLBACK bar_proc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
    case WM_PAINT: bar_paint(h); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_FLIM_STATUS:
        EnterCriticalSection(&g_netTextLock); SetWindowTextW(h, g_netText); LeaveCriticalSection(&g_netTextLock);
        InvalidateRect(h, NULL, FALSE); return 0;
    case WM_SETFOCUS: case WM_KILLFOCUS: InvalidateRect(h, NULL, FALSE); return 0;
    case WM_GETDLGCODE: return DLGC_WANTCHARS;
    case WM_KEYDOWN:
        if ((wp == VK_RETURN || wp == VK_SPACE) && g_pluginMissing) { plugins_dialog(h); return 0; }
        break;
    case WM_CONTEXTMENU:
        if (g_pluginMissing) { plugins_dialog(h); return 0; }
        break;
    case WM_FLIM_ALERT: {
        wchar_t w[400];
        EnterCriticalSection(&g_netTextLock);
        int info;
        MultiByteToWideChar(CP_UTF8, 0, g_alert, -1, w, 400);
        g_alert[0] = 0;
        info = g_alertInfo;
        LeaveCriticalSection(&g_netTextLock);
        if (!w[0]) return 0;
        { char hint[1200] = ""; WideCharToMultiByte(CP_UTF8, 0, w, -1, hint, sizeof(hint), NULL, NULL); fl_hint(hint); }
        logmsg("NOTICE %s: %S", info ? "info" : "error", w);
        return 0;
    }
    case WM_NOTIFY:
        if (((NMHDR *)lp)->code == TTN_GETDISPINFOW) {
            int cool = !(g_netState == NET_ON && g_endsAt);
            ((NMTTDISPINFOW *)lp)->lpszText = (LPWSTR)(cool
                ? L"Cooldown: after a session's time runs out, everyone in it waits 5 minutes before hosting or "
                  L"joining another one.\n\n" LIMIT_TEXTW
                : LIMIT_TEXTW);
            return 0;
        }
        break;
    case WM_TIMER:
        if (wp == CUR_TIMER) cursor_update();
        else {
            wchar_t tt[48];
            int cool, last;
            bar_layout();
            plugins_auto_tick(GetTickCount());
            if (bar_timer_text(tt, 48, &cool, &last) || g_timerRc.right) InvalidateRect(h, NULL, FALSE);   // the countdown
        }
        return 0;
    case WM_SETCURSOR: {
        POINT p; GetCursorPos(&p); ScreenToClient(h, &p);
        SetCursor(LoadCursor(NULL, p.x >= g_badgeEnd && g_pluginMissing ? IDC_HAND : IDC_ARROW));
        return TRUE;
    }
    case WM_MOUSEMOVE:
        if ((short)LOWORD(lp) >= g_badgeEnd && g_netState == NET_ON) {
            static char last[1200];
            char where[1200];
            focus_summary(where, sizeof(where), "   |   ");
            if (where[0] && strcmp(where, last) != 0) { strcpy_s(last, sizeof(last), where); fl_hint(where); }
        }
        return 0;
    case WM_LBUTTONDOWN:
        if ((short)LOWORD(lp) >= g_badgeEnd && g_pluginMissing) { SetFocus(h); plugins_dialog(h); }
        return 0;
    }
    return DefWindowProcW(h, m, wp, lp);
}

static BOOL CALLBACK find_toolbar_row(HWND h, LPARAM lp) {
    if (wnd_class_is(h, "TQuickEditToolBar")) { *(HWND *)lp = h; return FALSE; }
    return TRUE;
}

// Main thread only.
static void ui_create(void) {
    HWND row = NULL;
    if (g_netBar || !g_mainForm) return;
    EnumChildWindows(g_mainForm, find_toolbar_row, (LPARAM)&row);   // the first row (FILE EDIT ...)
    if (!row) { logmsg("UI: toolbar row not found"); return; }
    g_netRow = row;
    {   // sample the toolbar colour near the right end of the row (PrintWindow works even when FL is covered)
        RECT rr; GetClientRect(row, &rr);
        HDC dc = GetDC(row), full = CreateCompatibleDC(dc);
        HBITMAP fullBmp = CreateCompatibleBitmap(dc, rr.right, rr.bottom);
        HGDIOBJ of = SelectObject(full, fullBmp);
        HWND spl = FindWindowExW(row, NULL, L"TQuickEditToolbarPanel", L"Splitter_1");
        int sx = rr.right - 120;
        COLORREF c;
        if (spl) { RECT sr; GetWindowRect(spl, &sr); MapWindowPoints(NULL, row, (POINT *)&sr, 2); sx = sr.right - 20; }
        PrintWindow(row, full, PW_CLIENTONLY | 2 /* PW_RENDERFULLCONTENT */);
        c = GetPixel(full, sx, rr.bottom / 2);
        if (c != CLR_INVALID) g_toolbarBg = c;
        SelectObject(full, of); DeleteObject(fullBmp); DeleteDC(full);
        ReleaseDC(row, dc);
    }
    WNDCLASSW wc; memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = bar_proc;
    wc.hInstance = g_hinst;
    wc.lpszClassName = L"FlimNetBar";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);
    g_netBar = CreateWindowExW(0, L"FlimNetBar", L"flim", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_TABSTOP,
                               0, 0, 1, 1, row, NULL, g_hinst, NULL);
    if (!g_netBar) { logmsg("UI: CreateWindow failed %lu", GetLastError()); return; }
    bar_layout();
    SetTimer(g_netBar, 1, 1000, NULL);       // follow FL's window resizes
    SetTimer(g_netBar, CUR_TIMER, CUR_TIMER_MS, NULL);   // other people's arrows follow our scroll / zoom
    {   // tooltip over the timer (its rect follows the paint)
        INITCOMMONCONTROLSEX ic = { sizeof(ic), ICC_WIN95_CLASSES };
        TOOLINFOW ti;
        InitCommonControlsEx(&ic);
        g_tip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, NULL, WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
                                CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, g_netBar, NULL, g_hinst, NULL);
        if (g_tip) {
            memset(&ti, 0, sizeof(ti));
            ti.cbSize = TTTOOLINFOW_V2_SIZE; ti.uFlags = TTF_SUBCLASS; ti.hwnd = g_netBar; ti.uId = 1;
            ti.lpszText = LPSTR_TEXTCALLBACKW;
            SendMessageW(g_tip, TTM_ADDTOOLW, 0, (LPARAM)&ti);
            SendMessageW(g_tip, TTM_SETMAXTIPWIDTH, 0, 320);
            SendMessageW(g_tip, TTM_SETDELAYTIME, TTDT_AUTOPOP, 20000);
        }
    }
    if (g_alert[0]) PostMessageW(g_netBar, WM_FLIM_ALERT, 0, 0);
    {
        RECT b; GetWindowRect(g_netBar, &b);
        logmsg("UI net bar %p in toolbar row %p at %ld,%ld %ldx%ld (bg %06lx)", (void *)g_netBar, (void *)row,
               b.left, b.top, b.right - b.left, b.bottom - b.top, (unsigned long)g_toolbarBg);
    }
}

// ---------------- project sync ----------------
// A project load/new/close is never replayed piece by piece. The engine enters
// "project mode": nothing is sent, every param change is absorbed, and only project
// tasks run on FL's thread. When FL's load is over and things are quiet, all baselines
// are re-taken. The leader then sends the project FILE (members open the same .flp);
// a member that loaded something on its own asks the leader for its project instead.
// Both sides work on "<name>_flim_MMDD_hhmm.flp" so Ctrl+S never touches the original file
// and reopening the original never overwrites an earlier session's copy.
static volatile LONG  g_inHook = 0;
static volatile LONG  g_projBusy = 0;          // project mode
static volatile LONG  g_projRemote = 0;        // member: loading the leader's project
static volatile LONG  g_projDoneQueued = 0;
static volatile DWORD g_projSince = 0;
static volatile DWORD g_closingUntil = 0;      // FL is closing: never broadcast what teardown does
static volatile DWORD g_lastHookTick = 0;
static CRITICAL_SECTION g_heldLock;            // member: ops that arrived during a project load
typedef struct { char *msg; LONG gen; } HeldMsg;
static HeldMsg *g_held = NULL;
static int    g_nheld = 0, g_capheld = 0;
static size_t g_heldBytes;
#define HELD_MAX_COUNT 4096
#define HELD_MAX_BYTES (16u * 1024u * 1024u)

#define PROJ_SETTLE_MS  1500    // quiet time after FL's load before baselines are re-taken
#define PROJ_MAX_MS     180000  // give up waiting for quiet after this long

static void handle_msg(const char *m);

static int closing_now(void) { return g_closingUntil && (LONG)(GetTickCount() - g_closingUntil) < 0; }

static void fl_ustr(uint64_t va, wchar_t *out, int cap);
static wchar_t g_projNameAtBegin[MAX_PATH];     // FL's project file when the project change began

static void proj_begin(const char *why) {
    if (InterlockedExchange(&g_projBusy, 1) == 0) {
        fl_ustr(PROJNAME_VA, g_projNameAtBegin, MAX_PATH);
        g_projSince = GetTickCount();
        InterlockedExchange(&g_projRemote, 0);
        InterlockedExchange(&g_projDoneQueued, 0);
        logmsg("PROJECT change (%s): sync paused until FL settles", why);
    }
}

static void *fl_form(void) {
    __try { return **(void ***)(g_flBase + (MAINOBJ_VA - IMG_BASE)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return NULL; }
}
static void *fl_project(void) {
    __try { char *h = **(char ***)(g_flBase + (FLPROJ_VA - IMG_BASE)); return *(void **)(h + 0x10); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return NULL; }
}
// FL is inside an .flp load (its open handler parks a busy object on the form meanwhile).
static int fl_loading(void) {
    char *f = (char *)fl_form();
    if (!f) return 0;
    __try { return *(void **)(f + FORM_BUSY) != NULL; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
// Copy of one of FL's UnicodeString globals ('' if empty).
static void fl_ustr(uint64_t va, wchar_t *out, int cap) {
    out[0] = 0;
    __try {
        const wchar_t *s = *(const wchar_t **)(g_flBase + (va - IMG_BASE));
        if (s) wcsncpy_s(out, cap, s, _TRUNCATE);
    } __except (EXCEPTION_EXECUTE_HANDLER) { out[0] = 0; }
}
// A Delphi literal string FL may keep a pointer to: never freed (a few hundred bytes per load).
static wchar_t *dstr_keep(const wchar_t *s) {
    int n = (int)wcslen(s);
    unsigned char *m = (unsigned char *)calloc(1, 16 + (n + 1) * 2);
    if (!m) return NULL;
    *(uint16_t *)(m + 4) = 1200; *(uint16_t *)(m + 6) = 2;
    *(int32_t *)(m + 8) = -1;    *(int32_t *)(m + 12) = n;
    memcpy(m + 16, s, (size_t)n * 2);
    return (wchar_t *)(m + 16);
}

static unsigned char *read_file_w(const wchar_t *path, size_t *n) {
    FILE *f = NULL;
    *n = 0;
    if (!path || _wfopen_s(&f, path, L"rb") != 0 || !f) return NULL;
    return read_file_checked(f, n);
}
static HANDLE sibling_file_w(const wchar_t *path, wchar_t *temporary) {
    const wchar_t *slash, *other;
    size_t prefix;
    int tries;
    temporary[0] = 0;
    if (!path || !*path || wcsnlen_s(path, MAX_PATH) >= MAX_PATH) return INVALID_HANDLE_VALUE;
    slash = wcsrchr(path, L'\\'); other = wcsrchr(path, L'/');
    if (other && (!slash || other > slash)) slash = other;
    prefix = slash ? (size_t)(slash - path) + 1 : 0;
    if (prefix > MAX_PATH - 40) return INVALID_HANDLE_VALUE;
    for (tries = 0; tries < 16; tries++) {
        HANDLE file;
        memcpy(temporary, path, prefix * sizeof(wchar_t));
        swprintf_s(temporary + prefix, MAX_PATH - prefix, L".flim-%08lx-%08lx.tmp",
                   GetCurrentProcessId(), (DWORD)InterlockedIncrement(&g_tmpSeq));
        file = CreateFileW(temporary, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file != INVALID_HANDLE_VALUE) return file;
        if (GetLastError() != ERROR_FILE_EXISTS && GetLastError() != ERROR_ALREADY_EXISTS) break;
    }
    temporary[0] = 0;
    return INVALID_HANDLE_VALUE;
}
static int write_file_w(const wchar_t *path, const unsigned char *d, size_t n) {
    wchar_t temporary[MAX_PATH];
    HANDLE file;
    size_t offset = 0;
    int ok = 1;
    if ((!d && n) || n > FLIM_CLOUD_MAX) return 0;
    file = sibling_file_w(path, temporary);
    if (file == INVALID_HANDLE_VALUE) return 0;
    while (offset < n) {
        DWORD written = 0, bytes = (DWORD)((n - offset) > 1024 * 1024 ? 1024 * 1024 : n - offset);
        if (!WriteFile(file, d + offset, bytes, &written, NULL) || !written || written > bytes) { ok = 0; break; }
        offset += written;
    }
    if (ok && !FlushFileBuffers(file)) ok = 0;
    if (!CloseHandle(file)) ok = 0;
    if (ok) ok = MoveFileExW(temporary, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
    if (!ok) DeleteFileW(temporary);
    return ok;
}
static int copy_file_w(const wchar_t *source, const wchar_t *path) {
    wchar_t temporary[MAX_PATH];
    HANDLE file = sibling_file_w(path, temporary);
    int ok;
    if (file == INVALID_HANDLE_VALUE) return 0;
    ok = CloseHandle(file) != 0;
    if (ok) ok = CopyFileW(source, temporary, FALSE) != 0;
    if (ok) ok = SetFileAttributesW(temporary, FILE_ATTRIBUTE_NORMAL) != 0;
    if (ok) {
        file = CreateFileW(temporary, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE) ok = 0;
        else { ok = FlushFileBuffers(file) != 0; if (!CloseHandle(file)) ok = 0; }
    }
    if (ok) ok = MoveFileExW(temporary, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
    if (!ok) { SetFileAttributesW(temporary, FILE_ATTRIBUTE_NORMAL); DeleteFileW(temporary); }
    return ok;
}
static int file_exists_w(const wchar_t *p) {
    DWORD a = GetFileAttributesW(p);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}
static int ends_with_ci(const wchar_t *s, const wchar_t *suf) {
    size_t a = wcslen(s), b = wcslen(suf);
    return a >= b && _wcsicmp(s + a - b, suf) == 0;
}
static const wchar_t *base_name(const wchar_t *p) {
    const wchar_t *b = wcsrchr(p, L'\\'), *c = wcsrchr(p, L'/');
    if (c && (!b || c > b)) b = c;
    return b ? b + 1 : p;
}
// "<stem>_flim.flp" or "<stem>_flim_MMDD_hhmm.flp": already a session copy, work on it directly.
static int is_flim_name(const wchar_t *p) {
    size_t n = wcslen(p);
    int i;
    if (ends_with_ci(p, L"_flim.flp")) return 1;
    if (n < 19 || _wcsicmp(p + n - 4, L".flp") != 0) return 0;
    const wchar_t *t = p + n - 19;                     // "_flim_MMDD_hhmm.flp"
    if (_wcsnicmp(t, L"_flim_", 6) != 0 || t[10] != L'_') return 0;
    for (i = 6; i < 15; i++) if (i != 10 && !iswdigit(t[i])) return 0;
    return 1;
}
// path with its extension replaced by "_flim_MMDD_hhmm.flp" (local time).
static int flim_name(const wchar_t *path, wchar_t *out, int cap) {
    SYSTEMTIME st;
    const wchar_t *dot, *base;
    size_t n;
    if (!out || cap < 1) return 0;
    out[0] = 0;
    if (!path || !*path || wcsnlen_s(path, MAX_PATH) >= MAX_PATH) return 0;
    dot = wcsrchr(path, L'.'); base = base_name(path);
    n = dot && dot >= base ? (size_t)(dot - path) : wcslen(path);
    if (!*base || n + 20 > (size_t)cap) return 0;
    GetLocalTime(&st);
    memcpy(out, path, n * sizeof(wchar_t));
    swprintf_s(out + n, cap - n, L"_flim_%02d%02d_%02d%02d.flp", st.wMonth, st.wDay, st.wHour, st.wMinute);
    return 1;
}

// An existing file at p is kept as p.bak (replacing an older .bak) before p is rewritten.
static int backup_existing(const wchar_t *p) {
    wchar_t bak[MAX_PATH];
    DWORD attributes;
    if (!p || !*p || wcsnlen_s(p, MAX_PATH) + 4 >= MAX_PATH) return 0;
    attributes = GetFileAttributesW(p);
    if (attributes == INVALID_FILE_ATTRIBUTES) return GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND;
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) return 0;
    swprintf_s(bak, MAX_PATH, L"%s.bak", p);
    if (!copy_file_w(p, bak)) return 0;
    logmsg("PROJECT kept the previous copy as %S", bak);
    return 1;
}

// Make path FL's current project (title, Ctrl+S target, recent files). Main thread.
static int set_project_file(const wchar_t *path) {
    void *form = fl_form();
    wchar_t *w;
    if (!form || !path || !*path || wcsnlen_s(path, MAX_PATH) >= MAX_PATH) return 0;
    w = dstr_keep(path);
    if (!w) return 0;
    __try { ((setproj_t)(g_flBase + (SETPROJ_VA - IMG_BASE)))(form, w, w, 1); }
    __except (EXCEPTION_EXECUTE_HANDLER) { logmsg("PROJECT set name faulted"); return 0; }
    return 1;
}

// Re-take every baseline after a project change (main thread). Nothing is sent.
static void proj_rebaseline(void) {
    void **items; int n = chan_list(&items), i, t, s, k;
    known_from_list();
    memset(g_chU, 0, sizeof(g_chU));
    memset(g_fxU, 0, sizeof(g_fxU));
    plug_agreed_reset(1, 1);
    plugins_changed();
    memset(g_chanPlugN, 0, sizeof(g_chanPlugN));
    memset(g_fxN, 0, sizeof(g_fxN));
    for (i = 0; i < n; i++) g_chU[i].inst = plugin_inst(items[i]);
    for (t = 0; t < mix_count() && t < MAX_MIX; t++)
        for (s = 0; s < MAX_FX_SLOTS; s++) g_fxU[t][s].inst = plugin_inst(fx_obj(t, s));
    notes_rebaseline(0);
    rescan();
    for (k = 0; k < g_nslot; k++) {
        EnterCriticalSection(&g_slotLock);
        g_slots[k].last = read_value(g_slots[k].id);
        g_slots[k].lockedByMe = 0;
        InterlockedIncrement(&g_slots[k].gen);
        LeaveCriticalSection(&g_slotLock);
    }
    InterlockedIncrement(&g_structGen);
}

// {"t":"op","op":{"kind":"project.load","name":"<utf8>","data":"<b64>"}}
static void send_project(const unsigned char *d, size_t n, const wchar_t *name) {
    char nm[MAX_PATH * 3], esc[MAX_PATH * 6];
    int i, o = 0;
    nm[0] = 0;
    if (name && *name) WideCharToMultiByte(CP_UTF8, 0, name, -1, nm, sizeof(nm), NULL, NULL);
    for (i = 0; nm[i] && o < (int)sizeof(esc) - 7; i++) {
        unsigned char c = (unsigned char)nm[i];
        if (c == '"' || c == '\\') { esc[o++] = '\\'; esc[o++] = (char)c; }
        else if (c < 0x20) o += sprintf_s(esc + o, sizeof(esc) - o, "\\u%04x", c);
        else esc[o++] = (char)c;
    }
    esc[o] = 0;
    size_t cap = strlen(esc) + (n + 2) / 3 * 4 + 128;
    char *m = (char *)malloc(cap);
    if (!m) { sharing_fail("Project sync: session stopped", "There is not enough memory to send the shared project."); return; }
    int len = sprintf_s(m, cap, "{\"t\":\"op\",\"op\":{\"kind\":\"project.load\",\"name\":\"%s\",\"data\":\"", esc);
    b64enc(d, (int)n, m + len);
    strcat_s(m, cap, "\"}}");
    ws_send_samples(m, d, n);
    logmsg("PROJECT sent %S (%zu bytes)", (name && *name) ? name : L"(untitled)", n);
    /* FL's project saver may write a missing-plugin placeholder. Restore the retained
       presets after that snapshot, in the same ordered outbox, for late joiners. */
    for (i = 0; i < MAX_CH + MAX_MIX * MAX_FX_SLOTS; i++) {
        int unit = i < MAX_CH ? U_CH : U_FX;
        int a = i < MAX_CH ? i : (i - MAX_CH) / MAX_FX_SLOTS, b = i < MAX_CH ? 0 : (i - MAX_CH) % MAX_FX_SLOTS;
        Unit *u = unit_ptr(unit, a, b);
        if (u && u->unavailable) {
            size_t bytes;
            unsigned char *saved = plug_agreed_copy(unit, a, b, &bytes);
            if (!saved) { sharing_fail("Shared plugin: session stopped", "A retained plugin state could not be prepared for the joining member."); return; }
            send_unit("plug.state", unit, a, b, saved, bytes, NULL);
            free(saved);
        }
    }
    if (g_pluginMissing) send_full_state();
}

// Leader: snapshot of the current project (FL's own project writer; the current file
// name stays as it is). Returns malloc'd bytes or NULL. Main thread.
static unsigned char *project_snapshot(size_t *n) {
    wchar_t path[MAX_PATH];
    wchar_t *savedPath;
    char r = 0;
    *n = 0;
    if (strlen(g_tmpDir) + 40 >= MAX_PATH) return NULL;
    swprintf_s(path, MAX_PATH, L"%S\\snapshot_%ld.flp", g_tmpDir, InterlockedIncrement(&g_tmpSeq));
    savedPath = dstr_keep(path);
    if (!savedPath) return NULL;
    __try { r = ((saveproj_t)(g_flBase + (SAVEPROJ_VA - IMG_BASE)))(savedPath, 0); }
    __except (EXCEPTION_EXECUTE_HANDLER) { logmsg("PROJECT snapshot faulted"); r = 0; }
    if (!r) { logmsg("PROJECT snapshot failed"); DeleteFileW(path); return NULL; }
    unsigned char *d = read_file_w(path, n);
    DeleteFileW(path);
    return d;
}

// Leader, after a local load: work on <name>_flim_MMDD_hhmm.flp (a copy next to the original) and
// send that file to the members. Untitled projects (new from template) go as a snapshot.
static void leader_project_loaded(void) {
    wchar_t cur[MAX_PATH], flim[MAX_PATH];
    size_t n = 0;
    unsigned char *d = NULL;
    fl_ustr(PROJNAME_VA, cur, MAX_PATH);
    if (cur[0] && file_exists_w(cur)) {
        if (!is_flim_name(cur)) {
            if (!flim_name(cur, flim, MAX_PATH) || !backup_existing(flim) || !copy_file_w(cur, flim) || !set_project_file(flim)) {
                sharing_fail("Project copy failed: session stopped", "A separate working copy of your project could not be prepared. Move the project to a writable folder with a shorter path before reconnecting.");
                return;
            }
            logmsg("PROJECT working copy %S (original %S is never saved by flim sessions)", flim, cur);
            wcscpy_s(cur, MAX_PATH, flim);
        }
        d = project_snapshot(&n);
        if (d) { send_project(d, n, base_name(cur)); free(d); portable_send_peers(); return; }
    } else d = project_snapshot(&n);
    if (d) { send_project(d, n, NULL); free(d); portable_send_peers(); return; }
    sharing_fail("Project snapshot failed: session stopped", "FL Studio could not save a complete project snapshot. Check available disk space and the temporary folder before reconnecting.");
}

static void proj_end(void) {
    InterlockedExchange(&g_projDoneQueued, 0);
    InterlockedExchange(&g_projRemote, 0);
    InterlockedExchange(&g_projBusy, 0);
}

static void replay_held(void) {
    HeldMsg *h;
    int n, i;
    EnterCriticalSection(&g_heldLock);
    h = g_held; n = g_nheld;
    g_held = NULL; g_nheld = g_capheld = 0; g_heldBytes = 0;
    LeaveCriticalSection(&g_heldLock);
    if (n) logmsg("PROJECT replaying %d ops that arrived during the load", n);
    for (i = 0; i < n; i++) { if (h[i].gen == g_netGen) handle_msg(h[i].msg); free(h[i].msg); }
    free(h);
}

static void do_projdone(void) {
    int remote = g_projRemote, same = 0;
    {
        // a real load replaces every channel object; same objects = cancelled open (or a big
        // preset change that tripped the bulk guard): nothing to send. FL can reallocate the
        // new channels at the old addresses, so a changed project file also counts as a load.
        void **items; int n = chan_list(&items), i;
        wchar_t now[MAX_PATH];
        same = items && g_nChKnown > 0 && n == g_nChKnown;
        for (i = 0; same && i < n; i++) if (items[i] != g_chKnown[i]) same = 0;
        fl_ustr(PROJNAME_VA, now, MAX_PATH);
        if (_wcsicmp(now, g_projNameAtBegin) != 0) same = 0;
    }
    proj_rebaseline();
    if (same && !remote && !closing_now()) {
        logmsg("PROJECT unchanged after %lu ms (open cancelled?): nothing sent", GetTickCount() - g_projSince);
        proj_end();
        return;
    }
    if (closing_now()) { logmsg("PROJECT settled while FL is closing: nothing sent"); proj_end(); return; }
    logmsg("PROJECT settled after %lu ms (%d channels, %ld params)", GetTickCount() - g_projSince, g_nChKnown, g_nslot);
    if (remote) { proj_end(); replay_held(); return; }
    proj_end();
    if (g_isLeader) leader_project_loaded();
    else {
        logmsg("PROJECT loaded locally on a member: re-syncing to the leader's project");
        request_state();
    }
}

// Member: open the leader's project. it->path = UTF-16 path of the received file.
static void sharing_fail(const char *status, const char *why);
static void do_projload(const QItem *it) {
    const wchar_t *path = (const wchar_t *)it->path;
    void *form = fl_form(), *proj = fl_project();
    char r = 0;
    int began = 0, faulted = 0;
    DWORD t0 = GetTickCount();
    if (!form || !proj || !path || !*path || wcsnlen_s(path, MAX_PATH) >= MAX_PATH) {
        sharing_fail("Project loading failed: session stopped", "FL Studio was not ready to load the host's project. Reconnect after FL has finished starting.");
        return;
    }
    wchar_t *w = dstr_keep(path);
    if (!w) {
        sharing_fail("Project loading failed: session stopped", "There was not enough memory to load the host's project.");
        return;
    }
    __try {
        ((formfn_t)(g_flBase + (BUSYBEGIN_VA - IMG_BASE)))(form);
        began = 1;
        r = ((projload_t)(*(void ***)proj)[FLPROJ_LOAD_SLOT])(proj, w, 0);   // flags 0: no "save changes?" prompt
    } __except (EXCEPTION_EXECUTE_HANDLER) { faulted = 1; }
    if (began) {
        __try { ((formfn_t)(g_flBase + (BUSYEND_VA - IMG_BASE)))(form); }
        __except (EXCEPTION_EXECUTE_HANDLER) { faulted = 1; }
    }
    if (!r || faulted) {
        logmsg("PROJECT load failed %S ret=%d fault=%d in %lu ms", path, r, faulted, GetTickCount() - t0);
        sharing_fail("Project loading failed: session stopped", "FL Studio could not open the host's project. Check FL's error or license message before reconnecting.");
        return;
    }
    if (it->mode && !set_project_file(path)) {
        sharing_fail("Project save target failed: session stopped", "FL Studio opened the shared project, but its separate save location could not be confirmed. Use Save As to preserve your local changes before reconnecting.");
        return;
    }
    logmsg("PROJECT opened %S ret=%d in %lu ms", path, r, GetTickCount() - t0);
}

// Leader: a member asked for the project (join or re-sync).
static void do_projsnap(void) {
    wchar_t cur[MAX_PATH];
    size_t n = 0;
    unsigned char *d = project_snapshot(&n);
    if (!d) {
        sharing_fail("Project snapshot failed: session stopped", "FL Studio could not save a complete project snapshot for the joining member. Check available disk space and the temporary folder before reconnecting.");
        return;
    }
    fl_ustr(PROJNAME_VA, cur, MAX_PATH);
    send_project(d, n, cur[0] ? base_name(cur) : NULL);
    free(d);
}

// Member (recv thread): store the leader's project and queue the load.
static void on_project_load(const char *m) {
    if (g_portableLocal) { logmsg("PORTABLE skipped newer FL project; sharing notes and controls without opening newer project data"); return; }
    FlJson root = {m, strlen(m)}, op, value, data;
    wchar_t name[MAX_PATH], dir[MAX_PATH], path[MAX_PATH];
    char nm[MAX_PATH * 3];
    int i;
    size_t n = 0, bytes;
    unsigned char *d = NULL;
    QItem q = {0};
    if (!fj_get(root, "op", &op)) op = root;
    if (!fj_get(op, "name", &value) || !fj_text(value, nm, sizeof(nm)) ||
        !fj_get(op, "data", &value) || !shared_b64(value, &data, FLIM_CLOUD_MAX, &bytes) || !bytes) goto invalid;
    name[0] = 0;
    if (*nm && !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, nm, -1, name, MAX_PATH)) goto invalid;
    for (i = 0; name[i]; i++) if (wcschr(L"\\/:*?\"<>|", name[i])) name[i] = L'_';
    if (name[0] && !is_flim_name(name)) {                      // members also work on a session copy
        wchar_t tmp[MAX_PATH];
        if (!flim_name(name, tmp, MAX_PATH)) goto path_failed;
        wcscpy_s(name, MAX_PATH, tmp);
    }
    d = b64dec(data.p, data.n, &n);
    if (!d) return;
    {
        char theirs[32], mine[32];
        FlpBuildCheck check = flp_check_build(d, n, theirs, mine);
        if (check == FLP_BUILD_INVALID) {
            logmsg("PROJECT has an invalid or unverifiable FL build: not loaded, leaving the session");
            free(d);
            net_disconnect();
            net_status(NET_ERR, "Host project build could not be verified");
            net_alert("The host sent an invalid project snapshot, or its FL Studio build could not be verified.\n\n"
                      "flim left the session without loading it. Have the host save the project again before reconnecting.");
            return;
        }
        if (check == FLP_BUILD_MISMATCH) {
            logmsg("PROJECT made with FL %s, this is %s: not loaded, leaving the session", theirs, mine);
            free(d);
            net_disconnect();
            net_status(NET_ERR, "Host has another FL build (%s)", theirs);
            net_alert("This project was saved by FL %s; your FL is %s.\n\n"
                      "Use the oldest FL build as the host. flim will not load a newer project into an older FL, "
                      "or a project whose build differs from the negotiated host.", theirs, mine);
            return;
        }
    }
    logmsg("PROJECT compatible with FL %S (host %s); original version event preserved", g_fl.build, g_hostFlBuild);
    samples_rewrite(&d, &n);
    if (g_compatFault) { free(d); return; }
    if (name[0]) {
        int created;
        if (FAILED(SHGetFolderPathW(NULL, CSIDL_PERSONAL, NULL, SHGFP_TYPE_CURRENT, dir)) || !*dir ||
            wcslen(dir) + 6 >= MAX_PATH || wcslen(dir) + 7 + wcslen(name) >= MAX_PATH) goto path_failed;
        wcscat_s(dir, MAX_PATH, L"\\flim");
        created = SHCreateDirectoryExW(NULL, dir, NULL);
        if (created != ERROR_SUCCESS && created != ERROR_ALREADY_EXISTS && created != ERROR_FILE_EXISTS) goto path_failed;
        swprintf_s(path, MAX_PATH, L"%s\\%s", dir, name);
        if (!backup_existing(path)) goto path_failed;
    } else {
        if (strlen(g_tmpDir) + 40 >= MAX_PATH) goto path_failed;
        swprintf_s(path, MAX_PATH, L"%S\\project_%ld.flp", g_tmpDir, InterlockedIncrement(&g_tmpSeq));
    }
    q.path = (char *)_wcsdup(path);
    if (!q.path) goto path_failed;
    if (!write_file_w(path, d, n)) { free(q.path); goto path_failed; }
    free(d);
    // supersede anything queued or held from the previous project
    EnterCriticalSection(&g_heldLock);
    for (i = 0; i < g_nheld; i++) free(g_held[i].msg);
    g_nheld = 0; g_heldBytes = 0;
    LeaveCriticalSection(&g_heldLock);
    InterlockedExchange(&g_projBusy, 1);
    InterlockedExchange(&g_projRemote, 1);
    InterlockedExchange(&g_projDoneQueued, 0);
    g_projSince = GetTickCount();
    logmsg("PROJECT received %S (%zu bytes): loading", path, n);
    q.type = T_PROJLOAD;
    q.mode = name[0] != 0;
    enqueue(&q);
    return;
invalid:
    free(d);
    sharing_fail("Shared project: session stopped", "The shared project name or contents were incomplete or invalid. The previous local project was kept.");
    return;
path_failed:
    free(d);
    sharing_fail("Project save failed: session stopped", "The shared project could not be saved safely. Check disk space, folder permissions, and the project name length before reconnecting.");
}

// Member (recv thread): keep ops for after the load. Returns 1 if held.
static int hold_if_loading(const char *m) {
    size_t bytes;
    char *copy = NULL;
    int failed = 0;
    if (!g_projBusy || g_isLeader || !fj_member_is((FlJson){m, strlen(m)}, "t", "\"op\"")) return 0;
    bytes = strlen(m) + 1;
    EnterCriticalSection(&g_heldLock);
    if (g_nheld >= HELD_MAX_COUNT || bytes > HELD_MAX_BYTES - g_heldBytes || g_compatFault) failed = 1;
    if (!failed && g_nheld == g_capheld) {
        int cap = g_capheld ? g_capheld * 2 : 64;
        HeldMsg *items = (HeldMsg *)realloc(g_held, sizeof(HeldMsg) * cap);
        if (!items) failed = 1;
        else { g_held = items; g_capheld = cap; }
    }
    if (!failed && !(copy = _strdup(m))) failed = 1;
    if (!failed) {
        g_held[g_nheld].gen = session_generation();
        g_held[g_nheld++].msg = copy; g_heldBytes += bytes;
    }
    LeaveCriticalSection(&g_heldLock);
    if (failed) sharing_fail("Project edit backlog: session stopped", "Too many edits arrived while loading the project, or memory ran out. Reconnect and resync before continuing to share.");
    return 1;
}

// Poll thread, project mode: absorb everything, wait for FL's load to end and go quiet.
static void proj_poll(DWORD now) {
    static uint64_t sig = 0;
    static DWORD sigSince = 0, lastRescan = 0;
    int k, n, t, s, p;
    if (fl_loading() || g_inHook) { sigSince = now; return; }          // don't touch FL mid-load
    if (now - lastRescan > 500) { rescan(); lastRescan = now; }
    for (k = 0; k < g_nslot; k++) g_slots[k].last = read_value(g_slots[k].id);
    {
        void **items; uint64_t h = 1469598103934665603ull;
        n = chan_list(&items);
        for (k = 0; k < n && items; k++) { h ^= (uint64_t)(uintptr_t)items[k]; h *= 1099511628211ull; }
        for (t = 0; t < mix_count() && t < MAX_MIX; t++)
            for (s = 0; s < MAX_FX_SLOTS; s++) { h ^= (uint64_t)(uintptr_t)fx_obj(t, s); h *= 1099511628211ull; }
        for (p = 1; p < MAX_PAT; p += 1) { h ^= notes_hash(p); h *= 1099511628211ull; }
        h ^= (uint64_t)g_nslot * 0x9E3779B97F4A7C15ull;
        if (h != sig) { sig = h; sigSince = now; }
    }
    if (g_projDoneQueued) return;
    if ((now - g_projSince >= 1000 && now - sigSince >= PROJ_SETTLE_MS) || now - g_projSince > PROJ_MAX_MS) {
        InterlockedExchange(&g_projDoneQueued, 1);
        enqueue_unit(T_PROJDONE, 0, 0, 0, 0, NULL);
    }
}

// ---------------- pattern structure (insert, clone, delete, split...) ----------------
// These renumber patterns, so they can't travel as per-pattern edits (every later pattern would
// look changed). FL runs them as TFLProject virtual methods; we hook those vmt slots, send the
// call itself once FL has done it here (nothing if it was cancelled), and the peers make the same
// call. Afterwards both sides re-take their baselines: the renumbered patterns aren't edits.
// Open-array arguments arrive as (pointer, high index).
#define PATOP_N       6
static const int PATOP_SLOT[PATOP_N] = {
    0xd8,       // Clone(pats[])
    0xe0,       // Delete(pats[]): asks for confirmation
    0xe8,       // (pats[], a, target): drag-rearrange
    0xf0,       // (pats[], a, b, c)
    0xf8,       // Insert(pattern): "Insert one"
    0x100,      // SplitByChannel(pats[])
};
// Wire operation IDs stay stable when a build moves its virtual methods.
static uint32_t patop_vmt_slot(int k) {
    switch (k) {
    case 0: return g_fl.PATOP_CLONE_SLOT;
    case 1: return g_fl.PATOP_DELETE_SLOT;
    case 2: return g_fl.PATOP_REARRANGE_SLOT;
    case 3: return g_fl.PATOP_EDIT_SLOT;
    case 4: return g_fl.PATOP_INSERT_SLOT;
    case 5: return g_fl.PATOP_SPLIT_SLOT;
    default: return 0;
    }
}
#define PATOP_INSERT  4            // the one slot that takes a single pattern number
#define MSGBOX_VA     (g_fl.MSGBOX)        // FL's message box (text, flags, callback) -> button id (detoured)
#define MSGBOX_CORE_VA (g_fl.MSGBOX_CORE)  //   25.2: what it calls: (text, flags, 3, callback)
typedef uint64_t (*patop_t)(void *self, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e);
typedef int (*msgcore_t)(void *text, uint32_t flags, uint8_t kind, void *cb);
typedef int (*msgbox_t)(void *text, uint32_t flags, void *cb);
static msgbox_t g_mbOrig = NULL;          // 25.1: FL's message box, through a trampoline
static patop_t g_patOrig[PATOP_N];
static volatile LONG g_patRemote = 0;     // replaying a peer's op: don't send it back
static volatile LONG g_mbAuto = 0;        // main thread: FL message boxes are answered without showing

// Detour target for FL's message box. A peer's op must not wait for a dialog here: answer
// OK / Yes (what the peer already chose) while g_mbAuto is set; otherwise FL's own code.
static int msgbox_detour(void *text, uint32_t flags, void *cb) {
    if (g_mbAuto) {
        uint32_t t = flags & 0xf;
        logmsg("PATTERN op: answered FL's dialog (flags 0x%x)", flags);
        return (t == MB_YESNO || t == MB_YESNOCANCEL) ? IDYES : IDOK;
    }
    if (g_mbOrig) return g_mbOrig(text, flags, cb);
    return ((msgcore_t)(g_flBase + (MSGBOX_CORE_VA - IMG_BASE)))(text, flags, 3, cb);
}

// Everything a pattern op can renumber: notes, names, colors, lengths, markers.
static uint64_t pat_sig(void) {
    uint64_t h = 1469598103934665603ull, x;
    int p;
    for (p = 1; p < MAX_PAT; p++) {
        x = notes_hash(p); h = fnv_add(h, &x, 8);
        x = meta_hash(M_PAT, p); h = fnv_add(h, &x, 8);
        x = meta_hash(M_PMARK, p); h = fnv_add(h, &x, 8);
    }
    return h;
}

static uint64_t patop_common(int k, void *self, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) {
    int send = !g_patRemote && !g_patDepth && g_ws && !g_projBusy && !closing_now();
    uint64_t sig = send ? pat_sig() : 0, r;
    InterlockedIncrement(&g_patDepth);
    r = g_patOrig[k](self, a, b, c, d, e);
    InterlockedDecrement(&g_patDepth);
    if (!send) return r;
    if (pat_sig() == sig) { logmsg("PATTERN op 0x%x: nothing changed (cancelled?), not sent", PATOP_SLOT[k]); return r; }
    {
        char m[8192];
        int o = sprintf_s(m, sizeof(m), "{\"t\":\"op\",\"op\":{\"kind\":\"pat.op\",\"s\":%d,\"p\":[", PATOP_SLOT[k]);
        if (k == PATOP_INSERT) o += sprintf_s(m + o, sizeof(m) - o, "%d", (int)a);
        else {
            int i, n = (int)b + 1;
            __try { for (i = 0; i < n && i < MAX_PAT; i++) o += sprintf_s(m + o, sizeof(m) - o, "%s%d", i ? "," : "", ((int *)a)[i]); }
            __except (EXCEPTION_EXECUTE_HANDLER) { logmsg("PATTERN op 0x%x: bad pattern list, not sent", PATOP_SLOT[k]); return r; }
        }
        sprintf_s(m + o, sizeof(m) - o, "],\"a\":%d,\"b\":%d,\"c\":%u}}", (int)c, (int)d, (unsigned)(uint16_t)e);
        ws_send(m);
        logmsg("PATTERN op sent: %.200s", m);
    }
    notes_rebaseline(0);
    return r;
}
#define PATOP_HOOK(k) static uint64_t patop_hook##k(void *s, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) \
    { return patop_common(k, s, a, b, c, d, e); }
PATOP_HOOK(0) PATOP_HOOK(1) PATOP_HOOK(2) PATOP_HOOK(3) PATOP_HOOK(4) PATOP_HOOK(5)
static const patop_t PATOP_HOOKS[PATOP_N] = { patop_hook0, patop_hook1, patop_hook2, patop_hook3, patop_hook4, patop_hook5 };

// Once, when FL's project object exists: hook the vmt slots and detour the message box.
static void patops_install(void) {
    void **vmt;
    unsigned char *mb = (unsigned char *)(g_flBase + (MSGBOX_VA - IMG_BASE));
    unsigned char jmp[12] = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };   // mov rax, imm64; jmp rax
    void *target = (void *)msgbox_detour;
    DWORD old;
    uint32_t firstSlot = UINT32_MAX, lastSlot = 0;
    int k;
    char *proj = (char *)fl_project();
    if (!proj) { logmsg("PATTERN ops: no project object, not hooked"); return; }
    vmt = *(void ***)proj;
    // 25.2: the detour replaces the whole 12-byte wrapper. 25.1 has no wrapper: the detour goes over
    // the core's first 12 bytes (push r13 / rdi / rsi / rbx; sub rsp, 0x38; mov rbx, rcx - nothing
    // position-dependent), which run from a trampoline that jumps back behind them.
    // Either way: only over the exact bytes we know.
    if (memcmp(mb, g_fl.msgbox == 2 ? "\x41\x55\x57\x56\x53\x48\x83\xec\x38\x48\x89\xcb"
                                    : "\x48\x83\xec\x28\xb0\x03\x4d\x89\xc1\x41\x89\xc0", 12) != 0) {
        logmsg("PATTERN ops: FL's message box looks different, not hooked");
        return;
    }
    if (g_fl.msgbox == 2 && !g_mbOrig) {
        unsigned char *t = (unsigned char *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        void *back = mb + 12;
        if (!t) { logmsg("PATTERN ops: no trampoline memory, not hooked"); return; }
        memcpy(t, mb, 12);
        memcpy(t + 12, "\xFF\x25\x00\x00\x00\x00", 6);      // jmp [rip+0]
        memcpy(t + 18, &back, 8);
        FlushInstructionCache(GetCurrentProcess(), t, 26);
        g_mbOrig = (msgbox_t)t;
    }
    for (k = 0; k < PATOP_N; k++) {
        uint32_t slot = patop_vmt_slot(k);
        if (!slot || slot % sizeof(void *) || slot > 0x1000) { logmsg("PATTERN ops: invalid vmt slot"); return; }
        if (slot < firstSlot) firstSlot = slot;
        if (slot > lastSlot) lastSlot = slot;
    }
    if (!VirtualProtect((char *)vmt + firstSlot, lastSlot - firstSlot + sizeof(void *), PAGE_EXECUTE_READWRITE, &old)) { logmsg("PATTERN ops: vmt not writable"); return; }
    for (k = 0; k < PATOP_N; k++) {
        g_patOrig[k] = (patop_t)vmt[patop_vmt_slot(k) / sizeof(void *)];
        vmt[patop_vmt_slot(k) / sizeof(void *)] = (void *)PATOP_HOOKS[k];
    }
    VirtualProtect((char *)vmt + firstSlot, lastSlot - firstSlot + sizeof(void *), old, &old);
    memcpy(jmp + 2, &target, 8);
    if (VirtualProtect(mb, sizeof(jmp), PAGE_EXECUTE_READWRITE, &old)) {
        memcpy(mb, jmp, sizeof(jmp));
        VirtualProtect(mb, sizeof(jmp), old, &old);
        FlushInstructionCache(GetCurrentProcess(), mb, sizeof(jmp));
    }
    logmsg("PATTERN ops hooked (vmt %p)", (void *)vmt);
}

// Main thread, from the message hook (also inside modal loops): while a peer's op is replayed,
// FL's follow-up dialogs (Insert opens a rename box) are closed as if cancelled. The peer's
// own choice (e.g. the name) arrives as its own edit.
static BOOL CALLBACK close_name_dlg(HWND h, LPARAM lp) {
    DWORD pid = 0;
    (void)lp;
    GetWindowThreadProcessId(h, &pid);
    if (pid == GetCurrentProcessId() && IsWindowVisible(h) && wnd_class_is(h, "TNameEditForm")) {
        PostMessageW(h, WM_CLOSE, 0, 0);
        logmsg("PATTERN op: closed FL's rename box");
    }
    return TRUE;
}
static void patop_dialogs(void) {
    static DWORD last = 0;
    DWORD now = GetTickCount();
    if (!g_mbAuto || now - last < 50) return;
    last = now;
    EnumWindows(close_name_dlg, 0);
}

static void on_pat_op(const char *m) {
    QItem q; memset(&q, 0, sizeof(q));
    q.type = T_PATOP; q.path = _strdup(m);
    enqueue(&q);
}

// A peer's pattern op (main thread): the same call here, dialogs answered as the peer did.
static void do_patop(const QItem *it) {
    const char *m = it->path, *p, *end, *start;
    FlJson root = {m, strlen(m)}, op, value, patterns;
    int slot = 0, k, n = 0, a = 0, b = 0, c = 0, faulted = 0;
    unsigned char seen[MAX_PAT] = {0};
    static int pats[MAX_PAT];
    void *proj;
    if (!fj_get(root, "op", &op)) op = root;
    if (!fj_get(op, "s", &value) || !shared_int32(value, &slot) ||
        !fj_get(op, "p", &patterns) || patterns.n < 2 || patterns.p[0] != '[') goto invalid;
    for (k = 0; k < PATOP_N && PATOP_SLOT[k] != slot; k++) {}
    if (k == PATOP_N) goto invalid;
    p = patterns.p + 1; end = patterns.p + patterns.n - 1; fj_space(&p, end);
    while (p < end) {
        uint64_t pattern;
        start = p;
        if (n == MAX_PAT || !fj_value(&p, end, 0)) goto invalid;
        value.p = start; value.n = (size_t)(p - start);
        if (!fc_uint(value, &pattern) || !pattern || pattern >= MAX_PAT || seen[pattern]) goto invalid;
        seen[pattern] = 1; pats[n++] = (int)pattern;
        fj_space(&p, end);
        if (p < end) { if (*p++ != ',') goto invalid; fj_space(&p, end); }
    }
    if (!n || (k == PATOP_INSERT && n != 1) ||
        (fj_get(op, "a", &value) && !shared_int32(value, &a)) ||
        (fj_get(op, "b", &value) && !shared_int32(value, &b)) ||
        (fj_get(op, "c", &value) && (!shared_int32(value, &c) || c < 0 || c > 65535))) goto invalid;
    proj = fl_project();
    if (!proj || !g_patOrig[k]) {
        sharing_fail("Shared pattern operation: session stopped", "FL Studio is not ready to apply the shared pattern operation. Reconnect and resync before continuing to share.");
        return;
    }
    InterlockedExchange(&g_patRemote, 1);
    InterlockedExchange(&g_mbAuto, 1);
    InterlockedIncrement(&g_patDepth);
    __try {
        if (k == PATOP_INSERT) g_patOrig[k](proj, (uint64_t)(int64_t)pats[0], 0, 0, 0, 0);
        else g_patOrig[k](proj, (uint64_t)pats, (uint64_t)(int64_t)(n - 1), (uint64_t)(int64_t)a, (uint64_t)(int64_t)b, (uint64_t)(uint16_t)c);
    } __except (EXCEPTION_EXECUTE_HANDLER) { faulted = 1; logmsg("PATTERN op 0x%x faulted", slot); }
    InterlockedDecrement(&g_patDepth);
    InterlockedExchange(&g_mbAuto, 0);
    InterlockedExchange(&g_patRemote, 0);
    if (faulted) {
        sharing_fail("Shared pattern operation: session stopped", "FL Studio could not complete the shared pattern operation. Check your local patterns before reconnecting.");
        return;
    }
    notes_rebaseline(0);
    logmsg("PATTERN op applied: slot 0x%x, %d patterns (first %d)", slot, n, pats[0]);
    return;
invalid:
    sharing_fail("Shared pattern operation: session stopped", "The shared pattern operation is incomplete or invalid. Your local patterns were kept.");
}

// ---------------- unit locks (mutexing) ----------------
// Notes of a pattern ("pat:<n>") and the clips of an arrangement ("clips:<a>") sync as whole
// units, so two people editing the same unit at once would overwrite each other. Whoever
// changes a unit first takes its lock (server-arbitrated; ops carry the key and the server
// drops ops on keys someone else holds). While someone else holds it, a local change is
// reverted to the last agreed state and FL's hint bar says who is editing. A lock is released
// ULOCK_IDLE_MS after its owner's last change. Params keep their own per-param locks.
#define ULOCK_MAX      2048
#define ULOCK_IDLE_MS  2000
#define HINT_EVERY_MS  1500
typedef struct {
    char  key[32];
    int   mine;              // we hold it (granted or optimistically requested)
    int   granted;           // the server confirmed it
    int   peer;              // someone else holds it
    DWORD lastLocal;         // our last change under it
    DWORD lastHint;
    int   stateSent;         // plugin key: a plug.state went out under it before the grant
    char  owner[64];
} ULock;
static ULock g_ulocks[ULOCK_MAX];
static int   g_nulocks = 0;
static char  g_peersJson[4096];        // last welcome/presence message (id -> name for hints)

// Last agreed state per unit (what a revert restores) and our sent-but-unconfirmed state.
typedef struct { unsigned char *d; unsigned n; int known; } UState;
static UState g_patLast[MAX_PAT], g_patPend[MAX_PAT];
static UState g_clipLast, g_clipPend;
static int    g_clipLastArr = -1;

static int ustate_set(UState *s, const unsigned char *d, unsigned n, size_t rec) {
    unsigned char *copy;
    if (!rec || n > SIZE_MAX / rec || (n && !d)) return 0;
    copy = n ? (unsigned char *)malloc((size_t)n * rec) : NULL;
    if (n && !copy) return 0;
    if (n) memcpy(copy, d, (size_t)n * rec);
    free(s->d);
    s->d = copy;
    s->n = n; s->known = 1;
    return 1;
}
static void ustate_move(UState *dst, UState *src) { free(dst->d); *dst = *src; memset(src, 0, sizeof(*src)); }

static ULock *ulock_get(const char *key, int create) {
    int i;
    for (i = 0; i < g_nulocks; i++) if (strcmp(g_ulocks[i].key, key) == 0) return &g_ulocks[i];
    if (!create || g_nulocks >= ULOCK_MAX) return NULL;
    memset(&g_ulocks[g_nulocks], 0, sizeof(ULock));
    strcpy_s(g_ulocks[g_nulocks].key, sizeof(g_ulocks[0].key), key);
    return &g_ulocks[g_nulocks++];
}

static void peer_name(const char *id, char *out, int cap) {
    char pat[96];
    const char *p, *q;
    sprintf_s(pat, sizeof(pat), "\"id\":\"%s\",\"name\":\"", id);
    p = strstr(g_peersJson, pat);
    if (p && (p += strlen(pat), q = strchr(p, '"')) && q - p < cap) { memcpy(out, p, q - p); out[q - p] = 0; }
    else strcpy_s(out, cap, "another user");
}

// FL's hint bar (top left). Main thread. The string is kept: FL may hold on to it.
static void fl_hint(const char *msg) {
    wchar_t w[256];
    void *form = fl_form();
    if (!form) return;
    MultiByteToWideChar(CP_UTF8, 0, msg, -1, w, 256);
    __try { ((hint_t)(g_flBase + (HINT_VA - IMG_BASE)))(form, dstr_keep(w), 0); }
    __except (EXCEPTION_EXECUTE_HANDLER) { logmsg("hint faulted"); }
}

// "plug:ch:<i>" / "plug:fx:<track>:<slot>" -> unit. Returns 0 if key is no plugin key.
static int lock_index(const char *p, size_t n, unsigned limit, int *out) {
    FlJson value = {p, n}; uint32_t number;
    if (!fj_u32(value, &number) || number >= limit) return 0;
    *out = (int)number; return 1;
}
static int plug_parse(const char *key, int *unit, int *a, int *b) {
    const char *sep;
    *b = 0;
    if (!strncmp(key, "plug:ch:", 8) && lock_index(key + 8, strlen(key + 8), MAX_CH, a)) { *unit = U_CH; return 1; }
    if (!strncmp(key, "plug:fx:", 8) && (sep = strchr(key + 8, ':')) != NULL &&
        lock_index(key + 8, (size_t)(sep - key - 8), MAX_MIX, a) && lock_index(sep + 1, strlen(sep + 1), MAX_FX_SLOTS, b)) { *unit = U_FX; return 1; }
    return 0;
}
static int unit_key_valid(const char *key) {
    int unit, a, b;
    if (plug_parse(key, &unit, &a, &b)) return 1;
    if (!strncmp(key, "pat:", 4)) return lock_index(key + 4, strlen(key + 4), MAX_PAT, &a) && a;
    if (!strncmp(key, "clips:", 6)) return lock_index(key + 6, strlen(key + 6), 256, &a);
    return 0;
}

static void unit_label(const char *key, char *out, int cap) {
    int unit, a, b;
    if (strncmp(key, "pat:", 4) == 0) sprintf_s(out, cap, "Pattern %d", atoi(key + 4));
    else if (strncmp(key, "clips:", 6) == 0) strcpy_s(out, cap, "The playlist");
    else if (plug_parse(key, &unit, &a, &b)) {
        if (unit == U_FX) _snprintf_s(out, cap, _TRUNCATE, "Mixer insert %d slot %d", a, b + 1);
        else {
            char name[48] = "";
            __try {
                const wchar_t *w = *(const wchar_t **)((char *)chan_obj(a) + 0x50);   // CH_NAME
                if (w && !WideCharToMultiByte(CP_UTF8, 0, w, -1, name, sizeof(name), NULL, NULL)) name[0] = 0;
            } __except (EXCEPTION_EXECUTE_HANDLER) { name[0] = 0; }
            if (name[0]) _snprintf_s(out, cap, _TRUNCATE, "Channel '%s'", name);
            else _snprintf_s(out, cap, _TRUNCATE, "Channel %d", a + 1);
        }
    }
    else strcpy_s(out, cap, key);
}

static void hint_locked(ULock *l) {
    char who[64], what[96], msg[200];
    DWORD now = GetTickCount();
    if (now - l->lastHint < HINT_EVERY_MS) return;
    l->lastHint = now;
    peer_name(l->owner, who, sizeof(who));
    unit_label(l->key, what, sizeof(what));
    _snprintf_s(msg, sizeof(msg), _TRUNCATE, "%s is being edited by %s", what, who);
    fl_hint(msg);
}

// Before sending a local change of unit `key` (main thread). Returns 1 = go ahead (lock
// requested/held, op must carry the key), 0 = someone else holds it: caller reverts.
static int ulock_local(const char *key, int *already) {
    int r = 1;
    char m[96];
    EnterCriticalSection(&g_ulockLock);
    ULock *l = ulock_get(key, 1);
    *already = 0;
    if (!l) { LeaveCriticalSection(&g_ulockLock); return 1; }
    if (l->peer) { hint_locked(l); r = 0; }
    else {
        *already = l->granted;
        if (!l->mine) {
            l->mine = 1;
            sprintf_s(m, sizeof(m), "{\"t\":\"lock_acquire\",\"key\":\"%s\"}", key);
            ws_send(m);
        }
        l->lastLocal = GetTickCount();
    }
    LeaveCriticalSection(&g_ulockLock);
    return r;
}

// Poll thread: give back locks we stopped using.
static void ulock_release_idle(DWORD now) {
    int i;
    char m[96];
    EnterCriticalSection(&g_ulockLock);
    for (i = 0; i < g_nulocks; i++) {
        ULock *l = &g_ulocks[i];
        if (l->mine && now - l->lastLocal > ULOCK_IDLE_MS) {
            sprintf_s(m, sizeof(m), "{\"t\":\"lock_release\",\"key\":\"%s\"}", l->key);
            ws_send(m);
            l->mine = 0; l->granted = 0;
        }
    }
    LeaveCriticalSection(&g_ulockLock);
}

// State bookkeeping for a unit key. commit: our pending state becomes the agreed one.
static void unit_commit(const char *key) {
    if (strncmp(key, "pat:", 4) == 0) {
        int p = atoi(key + 4);
        if (p >= 1 && p < MAX_PAT && g_patPend[p].known) ustate_move(&g_patLast[p], &g_patPend[p]);
    } else if (strncmp(key, "clips:", 6) == 0 && g_clipPend.known) {
        ustate_move(&g_clipLast, &g_clipPend);
        g_clipLastArr = atoi(key + 6);
    }
}

// Main thread: restore the last agreed state of a unit (our change lost the lock race or
// was made while someone else held the lock).
static void unit_revert(const char *key) {
    unsigned char *d = NULL;
    unsigned n = 0;
    int known = 0, idx = -1, isPat = strncmp(key, "pat:", 4) == 0;
    int unit, a, b;
    if (plug_parse(key, &unit, &a, &b)) {
        // params were snapped back already (plug_undo); a state we sent was dropped by the server
        int sent = 0;
        EnterCriticalSection(&g_ulockLock);
        ULock *l = ulock_get(key, 0);
        if (l) { sent = l->stateSent; l->stateSent = 0; }
        LeaveCriticalSection(&g_ulockLock);
        if (sent) plug_revert_state(unit, a, b);
        logmsg("LOCK %s held by another user: local change reverted%s", key, sent ? " (state)" : "");
        return;
    }
    EnterCriticalSection(&g_ulockLock);
    if (isPat) {
        idx = atoi(key + 4);
        if (idx >= 1 && idx < MAX_PAT && g_patLast[idx].known) {
            known = 1; n = g_patLast[idx].n;
            if (n) {
                d = (unsigned char *)malloc((size_t)n * NOTE_SIZE);
                if (!d) { LeaveCriticalSection(&g_ulockLock); return; }
                memcpy(d, g_patLast[idx].d, (size_t)n * NOTE_SIZE);
            }
            free(g_patPend[idx].d); memset(&g_patPend[idx], 0, sizeof(UState));
        }
    } else if (strncmp(key, "clips:", 6) == 0) {
        idx = atoi(key + 6);
        if (g_clipLast.known && g_clipLastArr == idx) {
            known = 1; n = g_clipLast.n;
            if (n) {
                d = (unsigned char *)malloc((size_t)n * CLIP_SIZE);
                if (!d) { LeaveCriticalSection(&g_ulockLock); return; }
                memcpy(d, g_clipLast.d, (size_t)n * CLIP_SIZE);
            }
            free(g_clipPend.d); memset(&g_clipPend, 0, sizeof(UState));
        }
    }
    LeaveCriticalSection(&g_ulockLock);
    if (!known) { logmsg("LOCK %s: no agreed state to revert to", key); return; }
    if (isPat) notes_apply(idx, d, n); else clips_apply(idx, d, n);
    free(d);
    logmsg("LOCK %s held by another user: local change reverted", key);
}

static void do_unitrevert(const QItem *it) {
    unit_revert(it->path);
    EnterCriticalSection(&g_ulockLock);
    ULock *l = ulock_get(it->path, 0);
    if (l) hint_locked(l);
    LeaveCriticalSection(&g_ulockLock);
}

// Inbound lock messages for unit keys (recv thread). Returns 1 if handled.
static int on_unit_lock(const char *m) {
    FlJson root = {m, strlen(m)}, value;
    char key[32], owner[64] = "";
    int granted = 0, released = fj_member_is(root, "t", "\"lock_released\"");
    if (!fc_text(root, "key", key, sizeof(key)) || !unit_key_valid(key)) return 0;
    if (!released) {
        if (!fj_get(root, "granted", &value) || (!fj_is(value, "true") && !fj_is(value, "false")) ||
            !fc_text(root, "owner", owner, sizeof(owner)) || !owner[0] || !fc_target(owner)) return 1;
        granted = fj_is(value, "true");
    }
    EnterCriticalSection(&g_ulockLock);
    ULock *l = ulock_get(key, 1);
    if (l) {
        if (released) l->peer = 0;
        else if (strcmp(owner, g_myId) == 0) {
            if (granted) { l->mine = 1; l->granted = 1; l->peer = 0; l->stateSent = 0; unit_commit(key); plug_undo(key, 0); }
        } else {
            int lost = !granted;                     // denials go only to the side that asked: our change lost
            l->peer = 1; l->mine = 0; l->granted = 0;
            strcpy_s(l->owner, sizeof(l->owner), owner);
            if (lost) plug_undo(key, 1);             // plugin params we changed meanwhile: snap back
            if (lost) {
                QItem q; memset(&q, 0, sizeof(q));
                q.type = T_UNITREVERT; q.path = _strdup(key);
                enqueue(&q);
                logmsg("LOCK %s denied (held by %s): reverting our change", key, owner);
            }
        }
    }
    LeaveCriticalSection(&g_ulockLock);
    return 1;
}

// A remote change replaced a unit we had an unsent edit in: say who is editing it.
static void hint_if_held(const char *key) {
    EnterCriticalSection(&g_ulockLock);
    ULock *l = ulock_get(key, 0);
    if (l && l->peer) { hint_locked(l); logmsg("LOCK %s: our unsent edit was replaced by the lock holder's", key); }
    LeaveCriticalSection(&g_ulockLock);
}

// ---- plugin lock ----
// One lock per plugin (channel generator or mixer effect slot): "plug:ch:<i>" / "plug:fx:<t>:<s>".
// Any local change of the plugin takes it (a param tweak or a state change); param.set and
// plug.state ops carry it, so the server drops them while a peer holds it. While a peer holds
// it, local param tweaks snap back and a local state change is undone by reloading the last
// agreed state. A denied request (race) snaps back the params changed while it was pending.
static UState g_plugLastCh[MAX_CH];
static UState g_plugLastFx[MAX_MIX][MAX_FX_SLOTS];
static volatile DWORD g_hintQueuedAt = 0;

static void plug_key(int unit, int a, int b, char *key, int cap) {
    if (unit == U_CH) sprintf_s(key, cap, "plug:ch:%d", a);
    else sprintf_s(key, cap, "plug:fx:%d:%d", a, b);
}
static UState *plug_last(int unit, int a, int b) {
    if (unit == U_CH) return (a >= 0 && a < MAX_CH) ? &g_plugLastCh[a] : NULL;
    return (a >= 0 && a < MAX_MIX && b >= 0 && b < MAX_FX_SLOTS) ? &g_plugLastFx[a][b] : NULL;
}
// Plugin param id -> its unit. 0 for channel/mixer basics (vol, pan, route...): those keep per-param locks.
static int plug_param_unit(uint32_t id, int *unit, int *a, int *b) {
    return !IS_MUTE_ID(id) && (id & 0xFFFF) >= REC_PLUG_FIRST && unit_of_id(id, unit, a, b);
}

// Last agreed state of a plugin (.fst bytes): set on baseline, send and remote apply. NULL clears.
static int plug_agreed_set(int unit, int a, int b, const unsigned char *d, size_t n) {
    int ok = 1;
    EnterCriticalSection(&g_ulockLock);
    UState *s = plug_last(unit, a, b);
    if (s) {
        if (d && n) ok = n <= FLIM_CLOUD_MAX && ustate_set(s, d, (unsigned)n, 1);
        else { free(s->d); memset(s, 0, sizeof(*s)); }
    }
    LeaveCriticalSection(&g_ulockLock);
    if (!ok) sharing_fail("Shared plugin: session stopped", "There is not enough memory to preserve the shared preset. No placeholder state was sent.");
    return ok;
}

static unsigned char *plug_agreed_copy(int unit, int a, int b, size_t *n) {
    unsigned char *d = NULL;
    EnterCriticalSection(&g_ulockLock);
    UState *s = plug_last(unit, a, b);
    *n = 0;
    if (s && s->known && s->n) {
        d = (unsigned char *)malloc(s->n);
        if (d) { memcpy(d, s->d, s->n); *n = s->n; }
    }
    LeaveCriticalSection(&g_ulockLock);
    return d;
}

/* Keep unavailable states attached to their channels, never to the old rack index. */
static void plug_agreed_channels(const int *from, int n, int deleted) {
    static UState old[MAX_CH];
    int i;
    EnterCriticalSection(&g_ulockLock);
    for (i = 0; i < MAX_CH; i++) {
        old[i] = g_plugLastCh[i]; memset(&g_plugLastCh[i], 0, sizeof(UState));
        if (!g_chU[i].unavailable) { free(old[i].d); memset(&old[i], 0, sizeof(UState)); }
    }
    for (i = 0; i < n - (deleted >= 0); i++) {
        int src = from ? from[i] : i + (i >= deleted);
        g_plugLastCh[i] = old[src]; memset(&old[src], 0, sizeof(UState));
    }
    for (i = 0; i < MAX_CH; i++) free(old[i].d);
    LeaveCriticalSection(&g_ulockLock);
}

static int plug_param_blocked(uint32_t id) {
    int unit, a, b;
    Unit *u;
    return plug_param_unit(id, &unit, &a, &b) && (g_portableLocal || ((u = unit_ptr(unit, a, b)) && u->unavailable));
}
// Channel indices moved / project replaced: stored states no longer belong to their index.
static void plug_agreed_reset(int channels, int fx) {
    int i, j;
    EnterCriticalSection(&g_ulockLock);
    if (channels) for (i = 0; i < MAX_CH; i++) { free(g_plugLastCh[i].d); memset(&g_plugLastCh[i], 0, sizeof(UState)); }
    if (fx)
        for (i = 0; i < MAX_MIX; i++)
            for (j = 0; j < MAX_FX_SLOTS; j++) { free(g_plugLastFx[i][j].d); memset(&g_plugLastFx[i][j], 0, sizeof(UState)); }
    LeaveCriticalSection(&g_ulockLock);
}

static int load_queued(int unit, int a, int b) {
    int i, r = 0;
    EnterCriticalSection(&g_qLock);
    for (i = g_qh; i != g_qt && !r; i = (i + 1) % QCAP)
        r = g_q[i].type == T_LOAD && g_q[i].unit == unit && g_q[i].a == a && g_q[i].b == b;
    LeaveCriticalSection(&g_qLock);
    return r;
}

// Main thread: reload the plugin's last agreed state (our state change lost to the lock holder).
static void plug_revert_state(int unit, int a, int b) {
    unsigned char *d = NULL;
    unsigned n = 0;
    int failed = 0;
    if (load_queued(unit, a, b)) return;         // the holder's newer state is about to replace ours anyway
    EnterCriticalSection(&g_ulockLock);
    UState *s = plug_last(unit, a, b);
    if (s && s->known && s->n) {
        d = (unsigned char *)malloc(s->n);
        if (d) { memcpy(d, s->d, s->n); n = s->n; }
        else failed = 1;
    }
    LeaveCriticalSection(&g_ulockLock);
    if (failed) { sharing_fail("Shared plugin: session stopped", "There is not enough memory to restore the agreed plugin state."); return; }
    if (!d) { logmsg("PLUG %s %d/%d: no agreed state to revert to", unit == U_CH ? "ch" : "fx", a, b); return; }
    char *path = tmp_path("rv");
    if (!path) { free(d); return; }
    FILE *f = NULL;
    if (fopen_s(&f, path, "wb") == 0 && f) {
        failed = fwrite(d, 1, n, f) != n;
        if (fclose(f)) failed = 1;
    } else failed = 1;
    if (failed) {
        DeleteFileA(path); free(path);
        sharing_fail("Shared plugin: session stopped", "The agreed plugin state could not be written completely. Check free disk space before reconnecting.");
    } else {
        enqueue_unit(T_LOAD, unit, a, b, 0, path);
        logmsg("PLUG %s %d/%d: reverting to the agreed state (%u bytes)", unit == U_CH ? "ch" : "fx", a, b, n);
    }
    free(d);
}

// Main thread, before sending a plug.state: 1 = go ahead under *key, 0 = a peer holds the plugin.
static int plug_lock_send(int unit, int a, int b, char *key, int cap) {
    int already;
    plug_key(unit, a, b, key, cap);
    if (!ulock_local(key, &already)) return 0;
    if (!already) {
        EnterCriticalSection(&g_ulockLock);
        ULock *l = ulock_get(key, 0);
        if (l) l->stateSent = 1;
        LeaveCriticalSection(&g_ulockLock);
    }
    return 1;
}

// Poll thread, a local plugin param change: 1 = send it under *key, 0 = a peer holds the
// plugin (the caller snaps the param back). Changes made before the grant remember their
// previous value in case the request is denied.
static int plug_lock_param(int unit, int a, int b, Slot *s, uint32_t prev, char *key, int cap) {
    int r = 1;
    char m[96];
    plug_key(unit, a, b, key, cap);
    EnterCriticalSection(&g_ulockLock);
    ULock *l = ulock_get(key, 1);
    if (l && l->peer) r = 0;
    else if (l) {
        if (!l->mine) {
            l->mine = 1;
            sprintf_s(m, sizeof(m), "{\"t\":\"lock_acquire\",\"key\":\"%s\"}", key);
            ws_send(m);
        }
        if (!l->granted && !s->hasUndo) { s->undo = prev; s->hasUndo = 1; }
        l->lastLocal = GetTickCount();
    }
    LeaveCriticalSection(&g_ulockLock);
    return r;
}

// Lock answer for a plugin key: granted -> forget the undo values; denied -> apply them.
static void plug_undo(const char *key, int apply) {
    int unit, a, b, k, n = 0;
    if (!plug_parse(key, &unit, &a, &b)) return;
    for (k = 0; k < g_nslot; k++) {
        Slot *s = &g_slots[k];
        int u2, a2, b2;
        if (!s->hasUndo || !plug_param_unit(s->id, &u2, &a2, &b2) || u2 != unit || a2 != a || b2 != b) continue;
        if (apply) {
            Unit *u = unit_ptr(unit, a, b);
            LONG gen = u ? u->applyGen : 0;
            if (unit_poll_current(u, gen, GetTickCount())) { enqueue_local_revert(s->id, s->undo, gen); n++; }
        }
        s->hasUndo = 0;
    }
    if (n) logmsg("LOCK %s denied: %d params snapped back", key, n);
}

// Poll thread: show the hint for a held plugin (throttled; FL calls happen on the main thread).
static void enqueue_hint(const char *key) {
    DWORD now = GetTickCount();
    if (now - g_hintQueuedAt < HINT_EVERY_MS) return;
    g_hintQueuedAt = now;
    QItem q; memset(&q, 0, sizeof(q));
    q.type = T_HINT; q.path = _strdup(key);
    enqueue(&q);
}

static void do_hint(const QItem *it) {
    EnterCriticalSection(&g_ulockLock);
    ULock *l = ulock_get(it->path, 0);
    if (l && l->peer) hint_locked(l);
    LeaveCriticalSection(&g_ulockLock);
}

// ---- where everyone is working ----
// Each client tells the others which FL window it last clicked or typed in (its caption, e.g.
// "Piano roll - Kick · Pattern 3", "Mixer - Insert 2", a plugin's name). Shown after the status
// text, and in full in FL's hint bar when the mouse is over the flim status.
#define FOCUS_MAX     32
#define FOCUS_POLL_MS 300
typedef struct { char id[64]; char where[200]; } PeerFocus;
static PeerFocus g_focus[FOCUS_MAX];
static int g_nfocus = 0;                   // guarded by g_netTextLock
static volatile HWND g_focusHwnd = NULL;   // last window that got a click / key (main thread sets it)
static volatile LONG g_focusResend = 0;    // someone joined: tell them where we are

// Caption of the FL form h is in, without FL's icon glyphs (private-use characters).
static int focus_label(char *out, int cap) {
    HWND h = g_focusHwnd;
    wchar_t t[200], c[200];
    int i, o = 0;
    while (h && h != g_mainForm && !is_fl_form(h)) h = GetParent(h);
    if (!h || h == g_mainForm) return 0;                // toolbar, menus...: keep the last place
    InternalGetWindowText(h, t, 200);
    for (i = 0; t[i] && o < 190; i++) if (t[i] < 0xE000 || t[i] > 0xF8FF) c[o++] = t[i];
    while (o && (c[o - 1] == L' ' || c[o - 1] == L'-')) o--;
    c[o] = 0;
    if (!o) return 0;
    if (wnd_class_is(h, "TEventEditForm") && wcsncmp(c, L"Piano roll", 10) == 0) {
        int pat = 0;
        wchar_t nm[64] = L"";
        __try {
            pat = **(int **)(g_flBase + (g_fl.CURPAT - IMG_BASE));        // current pattern (what the piano roll edits)
            if (pat >= 1 && pat < MAX_PAT) {
                const wchar_t *n = *(const wchar_t **)(pat_rec(pat) + PAT_NAME);
                int k = ustr_len(n);
                if (k > 60) k = 60;
                if (k) { memcpy(nm, n, (size_t)k * 2); nm[k] = 0; }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { pat = 0; }
        if (pat >= 1 && pat < MAX_PAT) {
            if (nm[0]) swprintf_s(c + o, 200 - o, L" \x00B7 %s", nm);
            else swprintf_s(c + o, 200 - o, L" \x00B7 Pattern %d", pat);
        }
    }
    return WideCharToMultiByte(CP_UTF8, 0, c, -1, out, cap, NULL, NULL) > 1;
}

// Poll thread: send our place when it changed (or someone new is here).
static void focus_poll(DWORD now) {
    static DWORD last = 0;
    static char sent[200] = "";
    char cur[200], esc[420], m[512];
    if (now - last < FOCUS_POLL_MS || !g_ws) return;
    last = now;
    if (!focus_label(cur, sizeof(cur))) {
        if (!g_focusResend || !sent[0]) return;
        strcpy_s(cur, sizeof(cur), sent);
    }
    if (strcmp(cur, sent) == 0 && !InterlockedExchange(&g_focusResend, 0)) return;
    strcpy_s(sent, sizeof(sent), cur);
    json_esc(cur, esc, sizeof(esc));
    sprintf_s(m, sizeof(m), "{\"t\":\"op\",\"op\":{\"kind\":\"focus\",\"w\":\"%s\"}}", esc);
    ws_send(m);
}

// Inbound focus op (recv thread): {"t":"op","seq":..,"from":"<id>","op":{"kind":"focus","w":"..."}}
static void on_focus(const char *m) {
    FlJson root = {m, strlen(m)}, op, value;
    char id[64], where[200]; int i;
    if (!fc_text(root, "from", id, sizeof(id)) || !fc_target(id) || !id[0] ||
        !fj_get(root, "op", &op) || !fj_get(op, "w", &value) || !fj_decode(value, where, sizeof(where))) return;
    for (i = 0; where[i]; i++) if ((unsigned char)where[i] < 32) where[i] = ' ';
    EnterCriticalSection(&g_netTextLock);
    for (i = 0; i < g_nfocus && strcmp(g_focus[i].id, id); i++) {}
    if (i == g_nfocus && g_nfocus < FOCUS_MAX) strcpy_s(g_focus[g_nfocus++].id, sizeof(g_focus[0].id), id);
    if (i < g_nfocus) strcpy_s(g_focus[i].where, sizeof(g_focus[0].where), where);
    LeaveCriticalSection(&g_netTextLock);
    if (g_peersJson[0]) net_show_connected(g_peersJson);
}

// "Alex: Piano roll - Kick<sep>Bo: Mixer" for the people in the session now (any thread).
static void focus_summary(char *out, int cap, const char *sep) {
    int i, o = 0;
    out[0] = 0;
    EnterCriticalSection(&g_netTextLock);
    for (i = 0; i < g_nfocus; i++) {
        char pat[96], who[64];
        const char *p, *q;
        sprintf_s(pat, sizeof(pat), "\"id\":\"%s\",\"name\":\"", g_focus[i].id);
        if (!g_focus[i].where[0] || !(p = strstr(g_peersJson, pat))) continue;   // left the session
        p += strlen(pat);
        q = strchr(p, '"');
        if (!q || q - p >= (int)sizeof(who)) continue;
        memcpy(who, p, q - p); who[q - p] = 0;
        o += _snprintf_s(out + o, cap - o, _TRUNCATE, "%s%s: %s", o ? sep : "", who, g_focus[i].where);
        if (o < 0 || o >= cap - 1) break;
    }
    LeaveCriticalSection(&g_netTextLock);
}

// ---- where everyone is pointing ----
// While the mouse is over the piano roll's note grid or the playlist, its position goes out in
// song terms (tick + key, or tick + track), so it lands on the same note / bar for everyone
// whatever their zoom, scroll or window size. Each peer is shown as a small arrow with their name
// on top of our editor when it shows the same pattern / arrangement: click-through windows owned
// by FL's main form, hidden when something else covers that point of the editor.
#define PRFORM_VA (g_fl.PRFORM)    // global -> var -> piano roll form (NULL until first opened)
#define CURPAT_VA (g_fl.CURPAT)    // global -> int: current pattern (what the piano roll edits)
#define ED_HWND       0x45c        // editor form: window handle
#define ED_TICKSPERPX (g_fl.ED_TICKSPERPX)        //   double: ticks per pixel (horizontal zoom)
#define ED_HSCROLL    (g_fl.ED_HSCROLL)        //   int: horizontal scroll, pixels
#define PR_GRID       (g_fl.PR_GRID)        // piano roll form: TEventPanel_PR (note grid)
#define PL_GRID       (g_fl.PL_GRID)        // playlist form: TEventPanel_AU (clip grid)
#define CTL_BOUNDS    0x90         // control: Left, Top, Width, Height in its form's client area
#define GRID_VSCROLL  (g_fl.GRID_VSCROLL)        // grid panel: vertical scroll, pixels
#define PR_TOPKEY     (flim_profile_fl24(&g_fl) ? 0x3d4 : 0x418)
#define PR_KEYH       (flim_profile_fl24(&g_fl) ? 0x510 : 0x520)
#define TRK_TOP       0xb4         // playlist track (arrangement + t * 0x114): top y and height, pixels
#define TRK_H         0xb8
#define CUR_SEND_MS   80
#define CUR_STALE_MS  30000        // nothing from them for this long: hide (they walked away)
#define CUR_KEY       RGB(255, 0, 254)   // transparent colour of the arrow windows

typedef struct { HWND h; int L, T, W, H, hs, vs, topkey, keyh; double tpp; char *arr; } EdGeom;
typedef struct { char id[64]; char w[4]; int p, x, y, why; DWORD at; HWND ov; char name[64]; } PeerCursor;
static PeerCursor g_cur[FOCUS_MAX];
static int g_curNoCover = 0;               // FLIM_CURSOR_NOCOVER=1 (tests): show arrows even where FL is covered
static int g_ncur = 0;                     // guarded by g_netTextLock

// Where an editor's grid is and how it maps (any thread; FL's own fields, SEH-guarded).
// pl: 0 = piano roll, 1 = playlist. 0 = not there / not visible.
static int ed_geom(int pl, EdGeom *g) {
    __try {
        char *form = **(char ***)(g_flBase + ((pl ? PLFORM_VA : PRFORM_VA) - IMG_BASE)), *grid;
        if (!form) return 0;
        grid = *(char **)(form + (pl ? PL_GRID : PR_GRID));
        if (!grid) return 0;
        g->h = (HWND)(uintptr_t)*(uint32_t *)(form + ED_HWND);
        g->L = *(int *)(grid + CTL_BOUNDS); g->T = *(int *)(grid + CTL_BOUNDS + 4);
        g->W = *(int *)(grid + CTL_BOUNDS + 8); g->H = *(int *)(grid + CTL_BOUNDS + 12);
        g->tpp = *(double *)(form + ED_TICKSPERPX);
        g->hs = *(int *)(form + ED_HSCROLL);
        g->vs = *(int *)(grid + GRID_VSCROLL);
        g->topkey = *(int *)(grid + PR_TOPKEY);
        g->keyh = *(int *)(grid + PR_KEYH);
        g->arr = pl ? arr_obj(cur_arr()) : NULL;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    if (!g->h || !IsWindowVisible(g->h) || g->W <= 0 || g->H <= 0 || !(g->tpp > 0) || (!pl && g->keyh <= 0) || (pl && !g->arr)) return 0;
    return 1;
}
static int cur_pat(void) {
    __try { return **(int **)(g_flBase + (CURPAT_VA - IMG_BASE)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
}
// Playlist track t: top y and height in the grid (before scrolling).
static int trk_rows(char *arr, int t, int *top, int *h) {
    __try {
        *top = *(int *)(arr + (size_t)t * PL_TRK_STRIDE + TRK_TOP);
        *h = *(int *)(arr + (size_t)t * PL_TRK_STRIDE + TRK_H);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return 1;
}

// Screen point -> song position on editor pl: x = tick, y = key * 100 (piano roll) or
// track * 100 + percent into the track (playlist). 0 = not over that grid.
static int cur_from_screen(int pl, POINT s, int *ctx, int *x, int *y) {
    EdGeom g;
    HWND hw = WindowFromPoint(s);
    int t, top, h, yy;
    if (!ed_geom(pl, &g) || (hw != g.h && !IsChild(g.h, hw))) return 0;
    ScreenToClient(g.h, &s);
    s.x -= g.L; s.y -= g.T;
    if (s.x < 0 || s.y < 0 || s.x >= g.W || s.y >= g.H) return 0;
    *x = (int)((s.x + g.hs) * g.tpp);
    if (!pl) {
        *y = (int)(((double)g.topkey - (double)(s.y + g.vs) / g.keyh) * 100.0);
        *ctx = cur_pat();
        return *ctx >= 1;
    }
    yy = s.y + g.vs;
    for (t = 1; t <= PL_TRK_MAX && trk_rows(g.arr, t, &top, &h); t++)
        if (h > 0 && yy >= top && yy < top + h) { *y = t * 100 + (yy - top) * 100 / h; *ctx = cur_arr(); return 1; }
    return 0;
}

// Song position -> screen point on our editor pl. 1 = there, 0 = editor closed / scrolled away,
// -1 = covered by another window.
static int cur_to_screen(int pl, int x, int y, POINT *s) {
    EdGeom g;
    HWND hw;
    if (!ed_geom(pl, &g)) return 0;
    s->x = g.L + (int)(x / g.tpp) - g.hs;
    if (!pl) s->y = g.T + (int)(((double)g.topkey - y / 100.0) * g.keyh) - g.vs;
    else {
        int t = y / 100, top, h;
        if (t < 1 || t > PL_TRK_MAX || !trk_rows(g.arr, t, &top, &h)) return 0;
        s->y = g.T + top - g.vs + h * (y % 100) / 100;
    }
    if (s->x < g.L || s->y < g.T || s->x >= g.L + g.W || s->y >= g.T + g.H) return 0;
    ClientToScreen(g.h, s);
    hw = WindowFromPoint(*s);          // a plugin or another app on top? (our arrows let the point through)
    return g_curNoCover || hw == g.h || IsChild(g.h, hw) || wnd_class_is(hw, "FlimCursor") ? 1 : -1;
}

// Poll thread: tell the others where our mouse is (only while it is over a grid and moving).
static void cursor_poll(DWORD now) {
    static DWORD last = 0;
    static char sent[96] = "";
    char cur[96], m[192];
    POINT s;
    int pl, ctx = 0, x = 0, y = 0, on = 0;
    if (now - last < CUR_SEND_MS || !g_ws) return;
    last = now;
    if (GetCursorPos(&s))
        for (pl = 0; pl < 2 && !on; pl++)
            if (cur_from_screen(pl, s, &ctx, &x, &y)) {
                on = 1;
                sprintf_s(cur, sizeof(cur), "\"w\":\"%s\",\"p\":%d,\"x\":%d,\"y\":%d", pl ? "pl" : "pr", ctx, x, y);
            }
    if (!on) strcpy_s(cur, sizeof(cur), "\"w\":\"\"");
    if (strcmp(cur, sent) == 0) return;
    strcpy_s(sent, sizeof(sent), cur);
    sprintf_s(m, sizeof(m), "{\"t\":\"op\",\"op\":{\"kind\":\"cur\",%s}}", cur);
    ws_send(m);
}

// Inbound cur op (recv thread): {"t":"op",..,"from":"<id>","op":{"kind":"cur","w":"pr","p":3,"x":..,"y":..}}
static void on_cursor(const char *m) {
    FlJson root = {m, strlen(m)}, op, value;
    char id[64], window[8]; int i, p = 0, x = 0, y = 0, on;
    if (!fc_text(root, "from", id, sizeof(id)) || !id[0] || !fc_target(id) || !fj_get(root, "op", &op) ||
        !fc_text(op, "w", window, sizeof(window))) return;
    on = !strcmp(window, "pr") || !strcmp(window, "pl");
    if (!on && window[0]) return;
    if (on && (!fj_get(op, "p", &value) || !shared_int32(value, &p) || p < 0 ||
        (!strcmp(window, "pr") && (!p || p >= MAX_PAT)) ||
        !fj_get(op, "x", &value) || !shared_int32(value, &x) || x < 0 || x > 100000000 ||
        !fj_get(op, "y", &value) || !shared_int32(value, &y) || y < 0 || y > 100000000)) return;
    EnterCriticalSection(&g_netTextLock);
    for (i = 0; i < g_ncur && strcmp(g_cur[i].id, id); i++) {}
    if (i == g_ncur && g_ncur < FOCUS_MAX) { memset(&g_cur[i], 0, sizeof(g_cur[i])); g_cur[i].why = -1; strcpy_s(g_cur[g_ncur++].id, sizeof(g_cur[0].id), id); }
    if (i < g_ncur) {
        PeerCursor *c = &g_cur[i];
        strcpy_s(c->w, sizeof(c->w), window); c->p = p; c->x = x; c->y = y; c->at = GetTickCount();
    }
    LeaveCriticalSection(&g_netTextLock);
}

static COLORREF cursor_color(const char *id) {
    static const COLORREF pal[] = { RGB(0xff, 0x8a, 0x3d), RGB(0x3d, 0xc8, 0xff), RGB(0xb4, 0x6c, 0xff), RGB(0x5c, 0xe0, 0x7a),
                                    RGB(0xff, 0x5c, 0x8a), RGB(0xff, 0xd2, 0x3d), RGB(0x3d, 0xff, 0xd8), RGB(0xff, 0x6c, 0xff) };
    uint64_t h = fnv_add(1469598103934665603ull, id, strlen(id));
    return pal[h % (sizeof(pal) / sizeof(pal[0]))];
}
static HFONT cursor_font(int sc) {
    return CreateFontW(-13 * sc / 100, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, NONANTIALIASED_QUALITY, 0, L"Segoe UI");
}

// Arrow + name label; everything in CUR_KEY is see-through. GWLP_USERDATA = colour, "sc" = scale %.
static LRESULT CALLBACK cursor_proc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    if (m == WM_NCHITTEST) return HTTRANSPARENT;
    if (m == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        RECT rc, lb;
        SIZE ts;
        wchar_t name[64];
        int sc = (int)(intptr_t)GetPropW(h, L"sc"), n, k;
        HBRUSH bk = CreateSolidBrush(CUR_KEY), br = CreateSolidBrush((COLORREF)GetWindowLongPtrW(h, GWLP_USERDATA));
        HPEN pen = CreatePen(PS_SOLID, 1, RGB(0x20, 0x20, 0x20));
        HFONT f = cursor_font(sc);
        POINT arrow[7] = { {0, 0}, {0, 16}, {4, 12}, {7, 19}, {10, 18}, {7, 11}, {12, 11} };
        HGDIOBJ of, op, ob;
        GetClientRect(h, &rc);
        FillRect(dc, &rc, bk);
        for (k = 0; k < 7; k++) { arrow[k].x = arrow[k].x * sc / 100; arrow[k].y = arrow[k].y * sc / 100; }
        op = SelectObject(dc, pen); ob = SelectObject(dc, br); of = SelectObject(dc, f);
        Polygon(dc, arrow, 7);
        n = GetWindowTextW(h, name, 64);
        GetTextExtentPoint32W(dc, name, n, &ts);
        lb.left = 12 * sc / 100; lb.top = 16 * sc / 100;
        lb.right = lb.left + ts.cx + 8 * sc / 100; lb.bottom = lb.top + ts.cy + 2 * sc / 100;
        RoundRect(dc, lb.left, lb.top, lb.right, lb.bottom, 6 * sc / 100, 6 * sc / 100);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, RGB(0x10, 0x10, 0x10));
        TextOutW(dc, lb.left + 4 * sc / 100, lb.top + 1 * sc / 100, name, n);
        SelectObject(dc, of); SelectObject(dc, op); SelectObject(dc, ob);
        DeleteObject(f); DeleteObject(pen); DeleteObject(br); DeleteObject(bk);
        EndPaint(h, &ps);
        return 0;
    }
    if (m == WM_DESTROY) RemovePropW(h, L"sc");
    return DefWindowProcW(h, m, wp, lp);
}

static HWND cursor_window(const char *id, const char *name) {
    static int reg = 0;
    wchar_t wn[64];
    HDC dc = GetDC(g_mainForm);
    int sc = MulDiv(GetDeviceCaps(dc, LOGPIXELSY), 100, 96);
    HFONT f = cursor_font(sc);
    HGDIOBJ of = SelectObject(dc, f);
    SIZE ts;
    HWND h;
    if (!reg) {
        WNDCLASSW wc; memset(&wc, 0, sizeof(wc));
        wc.lpfnWndProc = cursor_proc; wc.hInstance = g_hinst; wc.lpszClassName = L"FlimCursor";
        RegisterClassW(&wc);
        reg = 1;
    }
    MultiByteToWideChar(CP_UTF8, 0, name, -1, wn, 64);
    GetTextExtentPoint32W(dc, wn, (int)wcslen(wn), &ts);
    SelectObject(dc, of); DeleteObject(f);
    ReleaseDC(g_mainForm, dc);
    h = CreateWindowExW(WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW, L"FlimCursor", wn, WS_POPUP,
                        0, 0, (12 + 8 + 2) * sc / 100 + ts.cx, (16 + 4) * sc / 100 + ts.cy, g_mainForm, NULL, g_hinst, NULL);
    if (!h) return NULL;
    SetLayeredWindowAttributes(h, CUR_KEY, 0, LWA_COLORKEY);
    SetWindowLongPtrW(h, GWLP_USERDATA, (LONG_PTR)cursor_color(id));
    SetPropW(h, L"sc", (HANDLE)(intptr_t)sc);
    return h;
}

// Main thread (net bar timer): place, show or hide every peer's arrow.
static void cursor_update(void) {
    DWORD now = GetTickCount();
    int i, live = g_netState == NET_ON && g_mainForm && !IsIconic(g_mainForm);
    EnterCriticalSection(&g_netTextLock);
    for (i = 0; i < g_ncur; i++) {
        PeerCursor *c = &g_cur[i];
        POINT s;
        char pat[96], name[64];
        const char *p = NULL, *q;
        int pl = c->w[1] == 'l', why;
        static const char *const WHY[] = { "shown", "not connected / FL minimized", "not over a grid", "idle",
                                           "left", "other pattern / arrangement", "not in view", "covered" };
        sprintf_s(pat, sizeof(pat), "\"id\":\"%s\",\"name\":\"", c->id);
        why = !live ? 1 : !c->w[0] ? 2 : now - c->at >= CUR_STALE_MS ? 3 : !(p = strstr(g_peersJson, pat)) ? 4 :
              c->p != (pl ? cur_arr() : cur_pat()) ? 5 : 0;
        if (!why) { int r = cur_to_screen(pl, c->x, c->y, &s); why = r > 0 ? 0 : r == 0 ? 6 : 7; }
        if (why != c->why) { c->why = why; logmsg("CURSOR %s: %s", c->id, WHY[why]); }
        if (why) {
            if (c->ov && IsWindowVisible(c->ov)) ShowWindow(c->ov, SW_HIDE);
            continue;
        }
        p += strlen(pat);
        q = strchr(p, '"');
        if (!q || q - p >= (int)sizeof(name)) continue;
        memcpy(name, p, q - p); name[q - p] = 0;
        if (c->ov && strcmp(name, c->name) != 0) { DestroyWindow(c->ov); c->ov = NULL; }   // renamed: new label size
        if (!c->ov) {
            strcpy_s(c->name, sizeof(c->name), name);
            if (!(c->ov = cursor_window(c->id, name))) continue;
        }
        SetWindowPos(c->ov, HWND_TOP, s.x, s.y, 0, 0, SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
    }
    LeaveCriticalSection(&g_netTextLock);
}

// Hooks for the notes / clips code ------------------------------------------------------
// Local change of a unit about to be sent (main thread). d = the records being sent.
// Returns 0 if someone else holds the unit: the caller reverts instead of sending.
static int unit_before_send(const char *key, int isPat, int idx, const unsigned char *d, unsigned n) {
    int already;
    if (!ulock_local(key, &already)) return 0;
    EnterCriticalSection(&g_ulockLock);
    if (!ustate_set(isPat ? &g_patPend[idx] : &g_clipPend, d, n, isPat ? NOTE_SIZE : CLIP_SIZE)) {
        LeaveCriticalSection(&g_ulockLock); return 0;
    }
    if (already) unit_commit(key);               // lock already ours: this state is agreed now
    LeaveCriticalSection(&g_ulockLock);
    return 1;
}
// A unit was replaced from outside (remote op / revert): that state is the agreed one.
static void unit_agreed(int isPat, int idx, const unsigned char *d, unsigned n) {
    EnterCriticalSection(&g_ulockLock);
    if (isPat) {
        if (idx >= 1 && idx < MAX_PAT && !ustate_set(&g_patLast[idx], d, n, NOTE_SIZE)) g_patLast[idx].known = 0;
    } else {
        if (!ustate_set(&g_clipLast, d, n, CLIP_SIZE)) g_clipLast.known = 0;
        g_clipLastArr = idx;
    }
    LeaveCriticalSection(&g_ulockLock);
}
// Baseline (start, project load, structural ops): the current state of every unit is agreed.
// Unlocked, SEH-guarded reads (as the hash scan does); selection bits cleared.
static void units_capture_all(void) {
    int p;
    unsigned i;
    EnterCriticalSection(&g_ulockLock);
    for (p = 1; p < MAX_PAT; p++) {
        __try {
            char *a = pat_notes_arr(p);
            unsigned n = a ? *(unsigned *)(a + NOTES_COUNT) : 0;
            if (n > 1000000) n = 0;
            if (!ustate_set(&g_patLast[p], n ? *(unsigned char **)(a + NOTES_DATA) : NULL, n, NOTE_SIZE)) {
                g_patLast[p].known = 0; continue;
            }
            for (i = 0; i < n; i++) g_patLast[p].d[(size_t)i * NOTE_SIZE + NOTE_SEL_OFS] &= (unsigned char)~NOTE_SEL_BIT;
        } __except (EXCEPTION_EXECUTE_HANDLER) { g_patLast[p].known = 0; }
    }
    __try {
        int arr = cur_arr();
        char *ca = arr_clips(arr);
        unsigned n = ca ? *(unsigned *)(ca + CLIPS_COUNT) : 0;
        if (!ca || n > 200000) { g_clipLast.known = 0; __leave; }
        unsigned char *wire = n ? clips_from_native(*(unsigned char **)(ca + CLIPS_DATA), n) : NULL;
        if (n && !wire) { g_clipLast.known = 0; __leave; }
        int stored = ustate_set(&g_clipLast, wire, n, CLIP_SIZE);
        free(wire);
        if (!stored) { g_clipLast.known = 0; __leave; }
        for (i = 0; i < n; i++) g_clipLast.d[(size_t)i * CLIP_SIZE + CLIP_SEL_OFS] &= (unsigned char)~CLIP_SEL_BIT;
        g_clipLastArr = arr;
    } __except (EXCEPTION_EXECUTE_HANDLER) { g_clipLast.known = 0; }
    LeaveCriticalSection(&g_ulockLock);
}

static void run_task(const QItem *it) {
    LONG previousGen = g_workGen; int previousBound = g_workBound;
    int remoteHeavy = it->type == T_LOAD || it->type == T_ADDCH || it->type == T_DELCH || it->type == T_FXCLEAR;
    EnterCriticalSection(&g_lifecycleLock);
    if (it->sessionGen != g_netGen || g_compatFault) { discard_task(it); LeaveCriticalSection(&g_lifecycleLock); return; }
    g_workBound = 1; g_workGen = it->sessionGen;
    if (remoteHeavy) wguard_begin();
    run_task_inner(it);
    if (remoteHeavy) wguard_pass();
    g_workGen = previousGen; g_workBound = previousBound;
    LeaveCriticalSection(&g_lifecycleLock);
}

static int recovery_checkpoint(void) {
    wchar_t dir[MAX_PATH], path[MAX_PATH], working[MAX_PATH]; SYSTEMTIME time; size_t n = 0;
    unsigned char *d = project_snapshot(&n); int created, ok;
    if (!d) return 0;
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_PERSONAL, NULL, SHGFP_TYPE_CURRENT, dir)) || wcslen(dir) + 90 >= MAX_PATH) { free(d); return 0; }
    wcscat_s(dir, MAX_PATH, L"\\flim\\recovery");
    created = SHCreateDirectoryExW(NULL, dir, NULL);
    if (created != ERROR_SUCCESS && created != ERROR_ALREADY_EXISTS && created != ERROR_FILE_EXISTS) { free(d); return 0; }
    GetLocalTime(&time);
    swprintf_s(path, MAX_PATH, L"%s\\before-join-%04u%02u%02u-%02u%02u%02u-%lu-%ld.flp", dir,
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond,
        GetCurrentProcessId(), InterlockedIncrement(&g_tmpSeq));
    ok = !file_exists_w(path) && write_file_w(path, d, n); free(d);
    if (ok) {
        logmsg("RECOVERY saved local project before portable join: %S", path);
        swprintf_s(working, MAX_PATH, L"%s\\session-%lu-%ld.flp", dir, GetCurrentProcessId(), InterlockedIncrement(&g_tmpSeq));
        ok = !file_exists_w(working) && copy_file_w(path, working) && set_project_file(working);
    }
    return ok;
}

static int portable_channels(int channels) {
    void **items; int i, n, had;
    if (channels < 0 || channels > MAX_CH) return 0;
    n = chan_list(&items);
    __try {
        for (i = n - 1; i >= 1; i--) {
            g_delChannel((unsigned)i, 0, DELCHAN_FLAGS);
            if (chan_list(&items) != i) return 0;
        }
        /* Keep another sampler present when replacing FL's last channel. */
        had = chan_list(&items);
        if (!g_addChannel(-1, 0, 1) || chan_list(&items) != had + 1) return 0;
        if (had) g_delChannel(0, 0, DELCHAN_FLAGS);
        if (chan_list(&items) != 1) return 0;
        for (i = 1; i < channels; i++) if (!g_addChannel(-1, 0, 1) || chan_list(&items) != i + 1) return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return 1;
}

static void portable_start(int channels) {
    int i, t, s;
    if (!g_portableLocal || channels < 0 || channels > MAX_CH) return;
    if (!recovery_checkpoint()) {
        sharing_fail("Recovery copy failed: sharing paused", "The local project could not be preserved before joining the newer host. Your local project was kept."); return;
    }
    InterlockedExchange(&g_projBusy, 1);
    InterlockedExchange(&g_projDoneQueued, 1);
    if (!portable_channels(channels)) { sharing_fail("Portable sync: sharing paused", "FL could not prepare the shared note channels. Your previous project is in the recovery folder."); proj_end(); return; }
    for (i = 1; i < MAX_PAT && !g_compatFault; i++) if (notes_hash(i)) notes_apply(i, NULL, 0);
    for (i = 0; i < arr_count() && !g_compatFault; i++) if (clips_hash(i)) clips_apply(i, NULL, 0);
    for (t = 0; t < mix_count() && t < MAX_MIX && !g_compatFault; t++) for (s = 0; s < MAX_FX_SLOTS && !g_compatFault; s++) {
        QItem clear = {0}; clear.a = t; clear.b = s; do_fxclear(&clear);
    }
    if (g_compatFault) { proj_end(); return; }
    proj_rebaseline();
    for (i = 0; i < channels; i++) g_chU[i].unavailable = 2;
    plugins_changed();
    proj_end();
    logmsg("PORTABLE ready: %d note channels; newer plugin/project data stays outside the older FL loader", channels);
    fl_hint("Connected to a newer FL host. Notes and shared controls sync automatically; unsupported sounds and playlist features are unavailable here.");
}

static void run_task_inner(const QItem *it) {
    switch (it->type) {
    case T_SNAP:   do_snap(it); break;
    case T_LOAD:   do_load(it); DeleteFileA(it->path); free(it->path); break;
    case T_ADDCH:  do_addch(it); DeleteFileA(it->path); free(it->path); break;
    case T_DELCH:  do_delch(it); break;
    case T_STRUCT: do_struct(); break;
    case T_FULL:   do_full(); break;
    case T_ORDER:  do_order(it); free(it->order); break;
    case T_FXCLEAR: do_fxclear(it); break;
    case T_FXSYNC: do_fxsync(it); free(it->order); break;
    case T_NOTESNAP: do_notesnap(it); break;
    case T_NOTEBASE: notes_rebaseline(0); break;
    case T_NOTES:  do_notes(it); free(it->order); break;
    case T_NOTESYNC: do_notesync(it); free(it->order); break;
    case T_PROJLOAD: do_projload(it); free(it->path); break;
    case T_PROJDONE: do_projdone(); break;
    case T_PROJSNAP: do_projsnap(); break;
    case T_CLIPSNAP: do_clipsnap(it); break;
    case T_CLIPS:  do_clips(it); free(it->order); break;
    case T_UNITREVERT: do_unitrevert(it); free(it->path); break;
    case T_HINT:   do_hint(it); free(it->path); break;
    case T_METASNAP: do_metasnap(it); break;
    case T_META:   do_meta(it); free(it->path); break;
    case T_PATOP:  do_patop(it); free(it->path); break;
    case T_PLUGRETRY: plugins_retry(); break;
    case T_PORTABLESEND: portable_send(it->path); free(it->path); break;
    case T_PORTABLESTART: portable_start(it->a); break;
    }
}

// ---------------- main-thread apply ----------------
static volatile LONG g_hookCalls = 0;

static void drain_queue_mainthread(void) {
    unsigned light = 0; DWORD started = GetTickCount();
    if (InterlockedExchange(&g_inHook, 1)) return;     // FL may pump messages inside a plugin load
    if (g_wguardUntil && GetTickCount() - g_wguardLast >= 30) wguard_pass();
    if (g_uiWanted && InterlockedExchange(&g_uiWanted, 0)) ui_create();
    for (;;) {
        QItem it;
        EnterCriticalSection(&g_qLock);
        if (g_qh == g_qt) { LeaveCriticalSection(&g_qLock); break; }
        it = g_q[g_qh]; g_qh = (g_qh + 1) % QCAP;
        LeaveCriticalSection(&g_qLock);

        if (it.sessionGen != g_netGen || g_compatFault ||
            (g_projBusy && it.type != T_PROJLOAD && it.type != T_PROJDONE && it.type != T_PROJSNAP)) {
            discard_task(&it);
            continue;
        }

        if (it.type != T_PARAM) {
            DWORD t0 = GetTickCount();
            int emptyBaseline = it.type == T_NOTES && it.b == 2 && it.mode == FNC_HEADER &&
                it.a > 0 && it.a < MAX_PAT && !g_noteSets[it.a].count && !notes_hash(it.a);
            run_task(&it);
            DWORD dt = GetTickCount() - t0;
            if (dt > 50) logmsg("SLOW main-thread task type=%d unit=%d %d/%d took %lu ms", it.type, it.unit, it.a, it.b, dt);
            if (emptyBaseline && ++light < 32 && GetTickCount() - started < 4) continue;
            // one heavy FL call per tick; come back for the rest
            if (g_qh != g_qt && g_mainWnd) PostMessageW(g_mainWnd, WM_NULL, 0, 0);
            break;
        }
        EnterCriticalSection(&g_lifecycleLock);
        if (it.sessionGen != g_netGen || g_compatFault || (it.mode == 1 && !unit_poll_current(param_unit(it.id), it.applyGen, GetTickCount()))) { LeaveCriticalSection(&g_lifecycleLock); continue; }
        if (plug_param_blocked(it.id)) {
            if (!it.mode) pend_put(it.id, it.v);
            LeaveCriticalSection(&g_lifecycleLock); continue;
        }
        Slot *s = slot_by_id(it.id);
        if (s) {
            // Record the value before writing so the poller sees no change, and bump
            // gen so any poll that raced with this write is discarded.
            EnterCriticalSection(&g_slotLock);
            s->last = it.v;
            InterlockedIncrement(&s->gen);
            LeaveCriticalSection(&g_slotLock);
        }
        uint32_t r = write_value(it.id, it.v);
        if (s) InterlockedIncrement(&s->gen);
        logmsg("APPLY id=0x%08x v=%u ret=%u", it.id, it.v, r);
        LeaveCriticalSection(&g_lifecycleLock);
        if (++light >= 64 || GetTickCount() - started >= 4) {
            if (g_qh != g_qt && g_mainWnd) PostMessageW(g_mainWnd, WM_NULL, 0, 0);
            break;
        }
    }
    InterlockedExchange(&g_inHook, 0);
}

static LRESULT CALLBACK getMsgHook(int code, WPARAM wp, LPARAM lp) {
    if (code >= 0 && lp) {
        const MSG *msg = (const MSG *)lp;
        switch (msg->message) {
        case WM_LBUTTONDOWN: case WM_RBUTTONDOWN: case WM_MBUTTONDOWN: case WM_KEYDOWN:
            g_focusHwnd = msg->hwnd;
            g_lastInput = GetTickCount();
            break;
        case WM_LBUTTONUP: case WM_RBUTTONUP: case WM_MOUSEWHEEL: case WM_KEYUP:
        case WM_SYSKEYDOWN: case WM_LBUTTONDBLCLK:
            g_lastInput = GetTickCount();
            break;
        case WM_MOUSEMOVE:
            if (msg->wParam & (MK_LBUTTON | MK_RBUTTON)) g_lastInput = GetTickCount();   // drags
            break;
        case WM_FL_OPENPROJ:
            if (msg->hwnd == g_mainForm) proj_begin("FL is opening a project");
            break;
        case WM_QUIT:
            g_closingUntil = GetTickCount() + 30000;
            proj_begin("FL is quitting");
            break;
        }
    }
    g_lastHookTick = GetTickCount();
    InterlockedIncrement(&g_hookCalls);
    if (g_mbAuto) patop_dialogs();
    if (code >= 0) drain_queue_mainthread();
    return CallNextHookEx(g_hook, code, wp, lp);
}

// Sent messages: closing FL (or Windows logoff) must never be broadcast as edits.
static HHOOK g_hookCwp = NULL;
static LRESULT CALLBACK callWndHook(int code, WPARAM wp, LPARAM lp) {
    if (code >= 0 && lp) {
        const CWPSTRUCT *c = (const CWPSTRUCT *)lp;
        if ((c->message == WM_CLOSE && (c->hwnd == g_mainForm || c->hwnd == g_mainWnd)) ||
            c->message == WM_QUERYENDSESSION || c->message == WM_ENDSESSION) {
            if (!closing_now()) logmsg("FL is closing (msg 0x%x): structural changes will not be sent", c->message);
            g_closingUntil = GetTickCount() + 30000;
            proj_begin("FL is closing");
        }
    }
    return CallNextHookEx(g_hookCwp, code, wp, lp);
}

static BOOL CALLBACK findMainForm(HWND h, LPARAM lp) {
    DWORD pid = 0;
    char c[64];
    GetWindowThreadProcessId(h, &pid);
    GetClassNameA(h, c, sizeof(c));
    if (pid == GetCurrentProcessId() && strcmp(c, "TFruityLoopsMainForm") == 0) { *(HWND *)lp = h; return FALSE; }
    return TRUE;
}

static int install_mainthread_hook(void) {
    HWND h = NULL;
    DWORD pid = 0, tid, getError, callError;
    HHOOK messages, calls;
    int tries;
    for (tries = 0; tries < 600 && !h; tries++) { EnumWindows(findMainForm, (LPARAM)&h); if (!h) Sleep(100); }
    if (!h) { logmsg("STARTUP FL main form not found within 60 seconds; sharing remains disabled"); return -1; }
    tid = GetWindowThreadProcessId(h, &pid);
    if (!tid || pid != GetCurrentProcessId()) {
        logmsg("STARTUP FL main form no longer belongs to this process; sharing remains disabled"); return -1;
    }
    // These callbacks are already loaded in the target process. Passing the DLL module
    // makes Windows resolve it again and can fail with ERROR_MOD_NOT_FOUND (126).
    messages = SetWindowsHookExW(WH_GETMESSAGE, getMsgHook, NULL, tid);
    getError = messages ? 0 : GetLastError();
    calls = SetWindowsHookExW(WH_CALLWNDPROC, callWndHook, NULL, tid);
    callError = calls ? 0 : GetLastError();
    if (!messages || !calls) {
        if (messages) UnhookWindowsHookEx(messages);
        if (calls) UnhookWindowsHookEx(calls);
        logmsg("STARTUP message hooks failed: get=%lu call=%lu; sharing remains disabled", getError, callError);
        return -1;
    }
    g_mainWnd = g_mainForm = h;
    g_hook = messages; g_hookCwp = calls;
    logmsg("STARTUP main form %p tid=%lu message hooks ready", (void *)h, tid);
    PostMessageW(h, WM_NULL, 0, 0);
    return 0;
}

// ---------------- detect ----------------
static void send_lock(const char *t, uint32_t id) {
    char m[96];
    sprintf_s(m, sizeof(m), "{\"t\":\"%s\",\"key\":\"param:%u\"}", t, id);
    ws_send(m);
}

// Which "container" an id belongs to (a channel, a mixer track, one effect slot).
// Used to tell a project load (many containers change at once) from a knob
// tweak or a preset change (one container).
static uint32_t container_of(uint32_t id) {
    if (IS_MUTE_ID(id)) return 0x20000u | (id & 0xFFFF);
    if (id >= 0x70000000u) return 0x10000u | ((id - 0x70000000u) >> 16);
    return id >> 16;
}

#define BULK_MIN_CHANGES    24
#define BULK_MIN_CONTAINERS 4

typedef struct { Slot *s; uint32_t prev, v; LONG gen, applyGen; } Change;
static Change g_changes[MAX_SLOTS];

// True if FL's channel list no longer matches what the main thread last recorded.
static int chan_list_changed(void) {
    void **items; int n = chan_list(&items), i;
    if (g_nChKnown < 0 || !items) return 0;
    if (n != g_nChKnown) return 1;
    for (i = 0; i < n; i++) if (items[i] != g_chKnown[i]) return 1;
    return 0;
}

// Decide when units need a state snapshot (runs on the poll thread; the
// snapshots themselves are queued for the main thread).
static void schedule_units(DWORD now) {
    static DWORD lastSweep = 0, lastStruct = 0;
    static int sweepPos = 0;
    int i, t, s, nch = g_nChKnown, nm = mix_count();
    if (now - lastStruct >= STRUCT_MS) { enqueue_unit(T_STRUCT, 0, 0, 0, 0, NULL); lastStruct = now; }
    if (nch < 0) return;
    for (i = 0; i < nch + nm * MAX_FX_SLOTS; i++) {
        int unit = i < nch ? U_CH : U_FX;
        int a = i < nch ? i : (i - nch) / MAX_FX_SLOTS, b = i < nch ? 0 : (i - nch) % MAX_FX_SLOTS;
        Unit *u = unit_ptr(unit, a, b);
        if (!u || u->unavailable) continue;
        if (unit_applying(u, now)) continue;
        if (unit == U_FX && !u->inst && !u->identAt) continue;
        if (u->addAt && now - u->addAt > SETTLE_IDENT_MS) {
            u->addAt = 0; u->identAt = 0; u->lastAct = 0;
            enqueue_unit(T_SNAP, unit, a, b, SNAP_ADD, NULL);
        } else if (u->identAt && now - u->identAt > SETTLE_IDENT_MS) {
            u->identAt = 0; u->lastAct = 0;
            enqueue_unit(T_SNAP, unit, a, b, SNAP_FORCE, NULL);
        } else if (!u->identAt && u->lastAct && now - u->lastAct > SETTLE_ACT_MS) {
            // a preset-sized burst may carry state params don't cover; plain knob
            // tweaks only move the baseline (a full reload on the peer would glitch audio)
            enqueue_unit(T_SNAP, unit, a, b, u->burst ? SNAP_IF_DIFF : SNAP_BASELINE, NULL);
            u->lastAct = 0; u->burst = 0;
        } else if (u->baselineAt && (LONG)(now - u->baselineAt) >= 0) {
            u->baselineAt = 0;
            enqueue_unit(T_SNAP, unit, a, b, SNAP_BASELINE, NULL);
        }
    }
    // Round-robin sweep: catches state changes that touch no params (e.g. Serum wavetables).
    if (now - lastSweep >= SWEEP_MS && g_lastInput && now - g_lastInput < INPUT_RECENT_MS) {
        int total = nch + nm * MAX_FX_SLOTS, tries;
        lastSweep = now;
        for (tries = 0; tries < total; tries++) {
            int k = (sweepPos++) % (total ? total : 1);
            int unit = k < nch ? U_CH : U_FX;
            int a = k < nch ? k : (k - nch) / MAX_FX_SLOTS, b = k < nch ? 0 : (k - nch) % MAX_FX_SLOTS;
            Unit *u = unit_ptr(unit, a, b);
            if (!u || u->unavailable || (unit == U_FX && !u->inst)) continue;
            if (u->lastAct || u->identAt || u->addAt || u->baselineAt || now < u->suppressUntil) continue;
            enqueue_unit(T_SNAP, unit, a, b, u->hash ? SNAP_IF_DIFF : SNAP_BASELINE, NULL);
            break;
        }
    }
    (void)t; (void)s;
}

static DWORD WINAPI pollThread(LPVOID p) {
    (void)p;
    DWORD lastScan = GetTickCount(), lastBeat = GetTickCount();
    LONG seenGen = g_structGen;
    for (;;) {
        g_workBound = 1; g_workGen = InterlockedCompareExchange(&g_netGen, 0, 0);
        DWORD now = GetTickCount();
        if (now - lastBeat > 30000) {
            int depth = (g_qt - g_qh + QCAP) % QCAP;
            logmsg("BEAT queue=%d inHook=%ld hookCalls=%ld chanChanged=%d known=%d", depth, g_inHook,
                   InterlockedExchange(&g_hookCalls, 0), chan_list_changed(), g_nChKnown);
            lastBeat = now;
        }
        int i, n, nc = 0;
        LONG gen0 = g_structGen;
        ulock_release_idle(now);
        if (g_projBusy) { proj_poll(now); Sleep(POLL_MS); continue; }
        if (chan_list_changed()) {
            // A channel was added/removed and the main thread hasn't processed it yet:
            // REC ids of later channels have shifted, so diffs would be garbage.
            int k;
            for (k = 0; k < g_nslot; k++) g_slots[k].last = read_value(g_slots[k].id);
            schedule_units(now);
            Sleep(POLL_MS);
            continue;
        }
        if (gen0 != seenGen) {
            // channel indices shifted (delete): re-read everything silently
            int k;
            for (k = 0; k < g_nslot; k++) g_slots[k].last = read_value(g_slots[k].id);
            seenGen = gen0;
        }
        if (now - lastScan > RESCAN_MS) { rescan(); retry_pending(); lastScan = now; }
        scan_notes(now);
        scan_clips(now);
        scan_meta(now);
        focus_poll(now);
        cursor_poll(now);
        n = g_nslot;
        for (i = 0; i < n; i++) {
            Slot *s = &g_slots[i];
            Unit *u = param_unit(s->id);
            if (plug_param_blocked(s->id)) continue;
            LONG ug = u ? u->applyGen : 0;
            if (ug & 1) continue;
            LONG g0 = s->gen;
            uint32_t v = read_value(s->id);
            if (s->gen != g0) continue;                 // raced with an apply; re-read next tick
            EnterCriticalSection(&g_slotLock);
            if (s->gen != g0 || (u && u->applyGen != ug)) { LeaveCriticalSection(&g_slotLock); continue; }
            uint32_t prev = s->last;
            if (v != prev) s->last = v;
            LeaveCriticalSection(&g_slotLock);
            if (v != prev && v != REC_NONE && prev != REC_NONE) {
                if (!unit_poll_current(u, ug, now)) continue;
                g_changes[nc].s = s; g_changes[nc].prev = prev; g_changes[nc].v = v;
                g_changes[nc].gen = g0; g_changes[nc].applyGen = ug; nc++;
            }
            if (s->lockedByMe && now - s->lastTouch > LOCK_IDLE_MS) {
                send_lock("lock_release", s->id);
                s->lockedByMe = 0;
            }
        }
        if (!session_current() || g_structGen != gen0) { Sleep(POLL_MS); continue; }   // indices moved mid-tick

        // per-unit activity: remember it, and flag preset-sized bursts
        // (a huge tick is a project load, handled by the bulk guard below)
        if (nc > 0 && nc < 2000) {
            static FlimUnitBurstCount counts[MAX_CH + MAX_MIX * MAX_FX_SLOTS];
            static uint32_t epoch;
            uint32_t tick = flim_unit_bursts_begin(counts, sizeof(counts) / sizeof(counts[0]), &epoch);
            for (i = 0; i < nc; i++) {
                int unit, a, b, key;
                Unit *u;
                if (!unit_of_id(g_changes[i].s->id, &unit, &a, &b) || !(u = unit_ptr(unit, a, b))) continue;
                key = unit == U_CH ? a : MAX_CH + a * MAX_FX_SLOTS + b;
                u->lastAct = now;
                if (flim_unit_bursts_hit(&counts[key], tick) >= BURST_PARAMS) u->burst = 1;
            }
        }
        schedule_units(now);

        if (nc >= BULK_MIN_CHANGES) {
            uint32_t seen[BULK_MIN_CONTAINERS];
            int ns = 0, j;
            for (i = 0; i < nc && ns < BULK_MIN_CONTAINERS; i++) {
                uint32_t c = container_of(g_changes[i].s->id);
                for (j = 0; j < ns && seen[j] != c; j++) {}
                if (j == ns) seen[ns++] = c;
            }
            if (ns >= BULK_MIN_CONTAINERS) {
                // Project load/new/revert: never broadcast as edits (see project sync).
                logmsg("BULK local change (%d values, >=%d containers)", nc, ns);
                proj_begin("bulk param change");
                Sleep(POLL_MS);
                continue;
            }
        }

        for (i = 0; i < nc; i++) {
            Slot *s = g_changes[i].s;
            if (s->gen != g_changes[i].gen || plug_param_blocked(s->id) || !unit_poll_current(param_unit(s->id), g_changes[i].applyGen, GetTickCount())) continue;
            char key[32];
            int unit, a, b;
            if (plug_param_unit(s->id, &unit, &a, &b)) {
                // plugin params go under their plugin's lock
                if (!plug_lock_param(unit, a, b, s, g_changes[i].prev, key, sizeof(key))) {
                    logmsg("LOCK %s held by another user: param 0x%08x snapped back", key, s->id);
                    enqueue_local_revert(s->id, g_changes[i].prev, g_changes[i].applyGen);
                    enqueue_hint(key);
                    continue;
                }
            } else {
                if (s->lockedByPeer) {
                    // someone else holds this knob: snap our local edit back
                    enqueue_local_revert(s->id, g_changes[i].prev, g_changes[i].applyGen);
                    continue;
                }
                if (!s->lockedByMe) { send_lock("lock_acquire", s->id); s->lockedByMe = 1; }
                s->lastTouch = now;
                sprintf_s(key, sizeof(key), "param:%u", s->id);
            }
            char op[160];
            sprintf_s(op, sizeof(op),
                "{\"t\":\"op\",\"op\":{\"kind\":\"param.set\",\"key\":\"%s\",\"id\":%u,\"v\":%u}}",
                key, s->id, g_changes[i].v);
            ws_send(op);
            logmsg("DETECT id=0x%08x %u -> %u (sent)", s->id, g_changes[i].prev, g_changes[i].v);
        }
        Sleep(POLL_MS);
    }
}

// ---------------- inbound ----------------
static int jget_u32(const char *s, const char *name, uint32_t *out) {
    FlJson root = {s, strlen(s)}, value;
    return fj_get(root, name, &value) && fj_u32(value, out);
}
static int jget_paramkey(const char *s, uint32_t *id) {
    FlJson root = {s, strlen(s)}, value; char key[48];
    if (!fj_get(root, "key", &value) || !fj_text(value, key, sizeof(key)) || strncmp(key, "param:", 6)) return 0;
    value.p = key + 6; value.n = strlen(key + 6);
    return fj_u32(value, id) && param_id_in_range(*id);
}

// Missing-plugin values remain bounded and coalesced here without touching FL.
#define MAX_PEND 8192
typedef struct { uint32_t id, v; LONG sessionGen; } Pend;
static Pend g_pend[MAX_PEND];
static int g_npend = 0;

static void pending_channels(const int *from, int n, int deleted) {
    int i, kept = 0;
    EnterCriticalSection(&g_qLock);
    for (i = 0; i < g_npend; i++) {
        Pend p = g_pend[i];
        if (p.id < 0x70000000u) {
            int old = (int)(p.id >> 16), next;
            if (old >= n || old == deleted) continue;
            if (from) { for (next = 0; next < n && from[next] != old; next++) {} }
            else next = old - (old > deleted);
            p.id = ((uint32_t)next << 16) | (p.id & 0xffff);
        }
        g_pend[kept++] = p;
    }
    g_npend = kept;
    LeaveCriticalSection(&g_qLock);
}

// Leader: send every known value so a joining member converges to our state.
static void send_full_state_to(const char *target) {
    int i, n = 0, cap = 64 + (g_nslot + MAX_PEND) * 24;
    char *buf = (char *)malloc(cap);
    if (!buf) { sharing_fail("Shared controls: session stopped", "There is not enough memory to prepare the shared controls."); return; }
    int o = sprintf_s(buf, cap, "{\"t\":\"op\",\"op\":{\"kind\":\"state.full\",\"vals\":[");
    for (i = 0; i < g_nslot; i++) {
        uint32_t v = g_slots[i].last;
        int unit, a, b;
        if (target && plug_param_unit(g_slots[i].id, &unit, &a, &b)) continue;
        if (v == REC_NONE || plug_param_blocked(g_slots[i].id)) continue;
        o += sprintf_s(buf + o, cap - o, "%s[%u,%u]", n ? "," : "", g_slots[i].id, v);
        n++;
    }
    EnterCriticalSection(&g_qLock);
    for (i = 0; i < g_npend; i++) {
        Pend p = g_pend[i];
        if (target) continue;
        if (p.sessionGen != g_netGen || !plug_param_blocked(p.id)) continue;
        o += sprintf_s(buf + o, cap - o, "%s[%u,%u]", n ? "," : "", p.id, p.v); n++;
    }
    LeaveCriticalSection(&g_qLock);
    sprintf_s(buf + o, cap - o, "]}}");
    ws_send_to(buf, target);
    free(buf);
    logmsg("STATE sent %d values", n);
}

static void send_full_state(void) { send_full_state_to(NULL); }

static int peer_id_valid(const char *id) {
    size_t n = strlen(id), i;
    if (!n || n > 64) return 0;
    for (i = 0; i < n; i++) if (!isalnum((unsigned char)id[i]) && id[i] != '_' && id[i] != '-') return 0;
    return 1;
}

static void ws_send_to(const char *msg, const char *target) {
    const char *op; size_t prefix, cap; char *out;
    if (!target) { ws_send(msg); return; }
    if (!peer_id_valid(target) || !(op = strstr(msg, "\"op\":{"))) return;
    prefix = (size_t)(op + 6 - msg); cap = strlen(msg) + strlen(target) + 16;
    out = (char *)malloc(cap);
    if (!out) { sharing_fail("Portable sync: sharing paused", "There is not enough memory to prepare the shared state."); return; }
    memcpy(out, msg, prefix);
    sprintf_s(out + prefix, cap - prefix, "\"for\":\"%s\",%s", target, msg + prefix);
    ws_send(out); free(out);
}

static void request_state(void) {
    ws_send(g_portableLocal ? "{\"t\":\"op\",\"op\":{\"kind\":\"state.req\",\"portable\":1}}" : "{\"t\":\"op\",\"op\":{\"kind\":\"state.req\"}}");
}

static void portable_send(const char *target) {
    void **items; int n, i; char start[128];
    if (!g_isLeader || !g_portableSync || !target || !peer_id_valid(target) || g_projBusy) return;
    n = chan_list(&items);
    sprintf_s(start, sizeof(start), "{\"t\":\"op\",\"op\":{\"kind\":\"portable.start\",\"nch\":%d}}", n);
    ws_send_to(start, target);
    send_notes_full_to(target);
    send_full_state_to(target);
    for (i = 0; i < n; i++) { char *m = meta_json(M_CHAN, i); if (m) { ws_send_to(m, target); free(m); } }
    for (i = 0; i < mix_count(); i++) {
        char *m = meta_json(M_MIX, i); if (m) { ws_send_to(m, target); free(m); }
        m = meta_json(M_ROUTE, i); if (m) { ws_send_to(m, target); free(m); }
    }
    for (i = 1; i < MAX_PAT; i++) if (notes_hash(i)) { char *m = meta_json(M_PAT, i); if (m) { ws_send_to(m, target); free(m); } }
    logmsg("PORTABLE sent notes and controls for %d channels to %s", n, target);
}

static void portable_send_peers(void) {
    FlJson root = {g_peersJson, strlen(g_peersJson)}, peers, item, value;
    const char *p, *end, *start; char id[65], version[32], mine[32];
    if (!g_portableSync || !g_isLeader || !fj_get(root, "peers", &peers) || peers.n < 2 ||
        !WideCharToMultiByte(CP_UTF8, 0, g_fl.build, -1, mine, sizeof(mine), NULL, NULL)) return;
    p = peers.p + 1; end = peers.p + peers.n - 1; fj_space(&p, end);
    while (p < end) {
        start = p; if (!fj_value(&p, end, 0)) return; item.p = start; item.n = (size_t)(p - start);
        if (fj_get(item, "id", &value) && fj_text(value, id, sizeof(id)) && strcmp(id, g_myId) &&
            fj_get(item, "fl", &value) && fj_text(value, version, sizeof(version)) && flim_version_family(version) && flim_version_cmp(version, mine) < 0)
            portable_send(id);
        fj_space(&p, end); if (p < end && *p++ != ',') return; fj_space(&p, end);
    }
}

// Inbound values for ids this FL doesn't have yet (still loading, plugin not
// scanned yet) wait here and are retried after each rescan.
static void pend_put(uint32_t id, uint32_t v) {
    int i, overflow = 0;
    LONG gen = session_generation();
    if (!session_current()) return;
    EnterCriticalSection(&g_qLock);
    for (i = 0; i < g_npend && g_pend[i].id != id; i++) {}
    if (i < g_npend) { g_pend[i].v = v; g_pend[i].sessionGen = gen; }
    else if (g_npend < MAX_PEND) { g_pend[g_npend].id = id; g_pend[g_npend].v = v; g_pend[g_npend].sessionGen = gen; g_npend++; }
    else overflow = 1;
    LeaveCriticalSection(&g_qLock);
    if (overflow) sharing_fail("Plugin controls: sharing paused", "Too many controls are waiting for unavailable plugins. Your local project was kept. Reconnect and resync before continuing.");
}

// Apply an inbound value (queued for the main thread). onlyIfDiff skips values
// we already have (join state). Returns 1 if an apply was queued.
static int route_inbound(uint32_t id, uint32_t v, int onlyIfDiff) {
    if (!param_id_in_range(id)) return 0;
    if (plug_param_blocked(id)) { enqueue_apply(id, v); return 1; }
    if (!add_slot(id)) { pend_put(id, v); return 0; }
    Slot *s = slot_by_id(id);
    if (onlyIfDiff && s && s->last == v) return 0;
    enqueue_apply(id, v);
    return 1;
}

static void retry_pending(void) {
    int i, kept = 0, applied = 0;
    EnterCriticalSection(&g_lifecycleLock);
    if (!session_current()) { LeaveCriticalSection(&g_lifecycleLock); return; }
    EnterCriticalSection(&g_qLock);
    for (i = 0; i < g_npend; i++) {
        Pend p = g_pend[i];
        if (p.sessionGen != g_netGen) continue;
        if (!param_id_in_range(p.id)) continue;
        if (plug_param_blocked(p.id)) { g_pend[kept++] = p; continue; }
        if (add_slot(p.id)) {
            Slot *s = slot_by_id(p.id);
            if (!s || s->last != p.v) { enqueue_apply(p.id, p.v); applied++; }
        } else g_pend[kept++] = p;
    }
    g_npend = kept;
    LeaveCriticalSection(&g_qLock);
    LeaveCriticalSection(&g_lifecycleLock);
    if (applied) logmsg("pending: applied %d, still waiting %d", applied, kept);
}

// Member: apply a state.full payload ("vals":[[id,v],...]).
typedef struct { uint32_t id, value; } IncomingParam;
static int incoming_param_cmp(const void *a, const void *b) {
    uint32_t x = ((const IncomingParam *)a)->id, y = ((const IncomingParam *)b)->id;
    return x < y ? -1 : x > y;
}
static void apply_full_state(const char *m) {
    FlJson root = {m, strlen(m)}, op, vals, pair, fields[2];
    const char *p, *end, *start;
    IncomingParam *parsed = NULL;
    unsigned count = 0, i, needed = 0; int diff = 0, capacity = 0;
    if (!fj_get(root, "op", &op) || !fj_get(op, "vals", &vals) || vals.n < 2 || vals.p[0] != '[') goto invalid;
    p = vals.p + 1; end = vals.p + vals.n - 1; fj_space(&p, end);
    while (p < end) {
        IncomingParam item;
        start = p;
        if (count == MAX_SLOTS + MAX_PEND || !fj_value(&p, end, 0)) goto invalid;
        pair.p = start; pair.n = (size_t)(p - start);
        if (!shared_array_fields(pair, fields, 2) || !fj_u32(fields[0], &item.id) ||
            !fj_u32(fields[1], &item.value) || !param_id_with_limit(item.id, MAX_MIX)) goto invalid;
        if (count == (unsigned)capacity) {
            IncomingParam *next; int cap = capacity ? capacity * 2 : 256;
            if (cap > MAX_SLOTS + MAX_PEND) cap = MAX_SLOTS + MAX_PEND;
            next = (IncomingParam *)realloc(parsed, (size_t)cap * sizeof(*next));
            if (!next) goto invalid;
            parsed = next; capacity = cap;
        }
        parsed[count++] = item;
        fj_space(&p, end);
        if (p < end) { if (*p++ != ',') goto invalid; fj_space(&p, end); if (p == end) goto invalid; }
    }
    if (count) qsort(parsed, count, sizeof(*parsed), incoming_param_cmp);
    for (i = 1; i < count; i++) if (parsed[i-1].id == parsed[i].id) goto invalid;
    /* Hold the queue until the complete snapshot has been reserved and routed. */
    EnterCriticalSection(&g_qLock);
    EnterCriticalSection(&g_slotLock);
    for (i = 0; i < count; i++) {
        Slot *slot;
        if (!param_id_in_range(parsed[i].id)) continue;
        slot = slot_by_id(parsed[i].id);
        if (g_portableLocal || plug_param_blocked(parsed[i].id) || !slot || slot->last != parsed[i].value) needed++;
    }
    LeaveCriticalSection(&g_slotLock);
    if (needed > (unsigned)(QCAP - 1 - (g_qt - g_qh + QCAP) % QCAP)) {
        LeaveCriticalSection(&g_qLock); goto invalid;
    }
    for (i = 0; i < count && !g_compatFault; i++) diff += route_inbound(parsed[i].id, parsed[i].value, !g_portableLocal);
    LeaveCriticalSection(&g_qLock);
    free(parsed);
    logmsg("STATE received %u values, %d differ (applying)", count, diff); return;
invalid:
    free(parsed);
    sharing_fail("Shared controls: sharing paused", "The complete control snapshot is invalid or could not be queued. Your local controls were kept. Reconnect and resync before continuing.");
}

// ---- inbound plugin state ----
static int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

// Decode base64 [s, s+n) into a new temp .fst; returns its path (malloc'd) or NULL.
static char *b64_to_tmpfile(const char *s, size_t n) {
    size_t o;
    unsigned char *out = b64dec(s, n, &o);
    if (!out) return NULL;
    samples_rewrite(&out, &o);
    if (g_compatFault) { free(out); return NULL; }
    char *path = tmp_path("in");
    FILE *f = NULL;
    int written = 0;
    if (!path) { free(out); return NULL; }
    if (fopen_s(&f, path, "wb") == 0 && f) {
        written = fwrite(out, 1, o, f) == o;
        if (fclose(f)) written = 0;
    }
    free(out);
    if (!written) {
        DeleteFileA(path); free(path);
        sharing_fail("Shared plugin: session stopped", "The received plugin file could not be written completely. Check free disk space before reconnecting.");
        return NULL;
    }
    return path;
}

static int int_after(const char *p, const char *end, const char *key, int *out) {
    const char *q = strstr(p, key);
    if (!q || (end && q > end)) return 0;
    *out = atoi(q + strlen(key));
    return 1;
}

typedef struct { int unit, a, b; FlJson data; char *path; char presetFl[32]; } IncomingUnit;
#define INCOMING_UNIT_MAX (MAX_CH + MAX_MIX * MAX_FX_SLOTS)

static int unit_fields(FlJson item, IncomingUnit *out) {
    FlJson value; uint64_t a, b = 0; size_t bytes;
    if (fj_get(item, "preset_fl", &value) && (!fj_text(value, out->presetFl, sizeof(out->presetFl)) || !flim_version_family(out->presetFl))) return 0;
    if (!fj_get(item, "unit", &value)) return 0;
    if (fj_is(value, "\"ch\"")) {
        out->unit = U_CH;
        if (!fj_get(item, "ch", &value) || !fc_uint(value, &a) || a >= MAX_CH) return 0;
    } else if (fj_is(value, "\"fx\"")) {
        out->unit = U_FX;
        if (!fj_get(item, "trk", &value) || !fc_uint(value, &a) || a >= MAX_MIX ||
            !fj_get(item, "slot", &value) || !fc_uint(value, &b) || b >= MAX_FX_SLOTS) return 0;
    } else return 0;
    if (!fj_get(item, "data", &value) || !shared_b64(value, &out->data, 48 * 1024 * 1024, &bytes) || !bytes) return 0;
    out->a = (int)a; out->b = (int)b;
    return 1;
}

static const char *parse_unit(const char *m, int *unit, int *a, int *b, char **path) {
    FlJson root = {m, strlen(m)}, op, kind;
    IncomingUnit parsed = {0};
    *path = NULL;
    if (!fj_get(root, "op", &op)) op = root;
    if (!unit_fields(op, &parsed) ||
        (fj_get(op, "kind", &kind) && fj_is(kind, "\"chan.add\"") && parsed.unit != U_CH)) {
        sharing_fail("Shared plugin: session stopped", "The shared plugin data or target is incomplete or invalid. Your local plugin was kept.");
        return NULL;
    }
    *unit = parsed.unit; *a = parsed.a; *b = parsed.b;
    *path = b64_to_tmpfile(parsed.data.p, parsed.data.n);
    return *path ? m + strlen(m) : NULL;
}

// Prepare the entire replacement before any channel deletion or empty-slot cleanup is queued.
static void apply_plug_full(const char *m) {
    FlJson root = {m, strlen(m)}, op, value, items;
    IncomingUnit *units = NULL;
    QItem *tasks = NULL;
    unsigned char *keep = NULL;
    uint64_t nch;
    const char *p, *end, *start;
    void **list;
    int k, count = 0, local, ntask = 0, failed = 0;
    LONG generation = session_generation();
    if (!fj_get(root, "op", &op)) op = root;
    if (!fj_get(op, "nch", &value) || !fc_uint(value, &nch) || nch > MAX_CH ||
        !fj_get(op, "items", &items) || items.n < 2 || items.p[0] != '[') goto invalid;
    units = (IncomingUnit *)calloc(INCOMING_UNIT_MAX, sizeof(*units));
    keep = (unsigned char *)calloc(MAX_MIX * MAX_FX_SLOTS, 1);
    if (!units || !keep) goto memory;
    p = items.p + 1; end = items.p + items.n - 1; fj_space(&p, end);
    while (p < end) {
        IncomingUnit parsed = {0}; FlJson item; int index;
        start = p;
        if (!fj_value(&p, end, 0)) goto invalid;
        item.p = start; item.n = (size_t)(p - start);
        if (!unit_fields(item, &parsed) || (parsed.unit == U_CH && parsed.a >= (int)nch)) goto invalid;
        index = parsed.unit == U_CH ? parsed.a : MAX_CH + parsed.a * MAX_FX_SLOTS + parsed.b;
        if (units[index].data.p) goto invalid;
        units[index] = parsed; count++;
        if (parsed.unit == U_FX) keep[index - MAX_CH] = 1;
        fj_space(&p, end);
        if (p < end) { if (*p++ != ',') goto invalid; fj_space(&p, end); }
    }
    for (k = 0; k < (int)nch; k++) if (!units[k].data.p) goto invalid;
    local = chan_list(&list);
    tasks = (QItem *)calloc((size_t)count + (local > (int)nch ? local - (int)nch : 0) + 1, sizeof(*tasks));
    if (!tasks) goto memory;
    for (k = 0; k < INCOMING_UNIT_MAX; k++) if (units[k].data.p) {
        units[k].path = b64_to_tmpfile(units[k].data.p, units[k].data.n);
        if (!units[k].path) goto cleanup;
    }
    for (k = local - 1; k >= (int)nch; k--) {
        tasks[ntask].type = T_DELCH; tasks[ntask].unit = U_CH; tasks[ntask++].a = k;
    }
    for (k = 0; k < INCOMING_UNIT_MAX; k++) if (units[k].data.p) {
        QItem *task = &tasks[ntask++]; IncomingUnit *u = &units[k];
        task->type = u->unit == U_CH && u->a >= local ? T_ADDCH : T_LOAD;
        task->unit = u->unit; task->a = u->a; task->b = u->b;
        task->mode = task->type == T_LOAD; task->path = u->path;
        strcpy_s(task->presetFl, sizeof(task->presetFl), u->presetFl);
        if (u->presetFl[0]) { char mine[32];
            if (!WideCharToMultiByte(CP_UTF8, 0, g_fl.build, -1, mine, sizeof(mine), NULL, NULL) || flim_version_cmp(u->presetFl, mine) > 0) task->mode = 3;
        }
    }
    tasks[ntask].type = T_FXSYNC; tasks[ntask++].order = (int *)keep;
    EnterCriticalSection(&g_qLock);
    if (generation != g_netGen || g_compatFault) failed = 1;
    else if (ntask > (g_qh + QCAP - g_qt - 1) % QCAP) failed = 2;
    else for (k = 0; k < ntask; k++) {
        tasks[k].sessionGen = generation;
        g_q[g_qt] = tasks[k]; g_qt = (g_qt + 1) % QCAP;
    }
    LeaveCriticalSection(&g_qLock);
    if (failed) {
        if (failed == 2) sharing_fail("Edit backlog: session stopped", "There is not enough room to apply the complete plugin snapshot. Your local channels and plugins were kept.");
        goto cleanup;
    }
    for (k = 0; k < INCOMING_UNIT_MAX; k++) units[k].path = NULL;
    keep = NULL;
    if (g_mainWnd) PostMessageW(g_mainWnd, WM_NULL, 0, 0);
    logmsg("PLUG full state received: leader has %u channels, %d units queued", (unsigned)nch, count);
    goto cleanup;
invalid:
    sharing_fail("Shared plugins: session stopped", "The complete plugin snapshot is incomplete or invalid. Your local channels and plugins were kept.");
    goto cleanup;
memory:
    sharing_fail("Shared plugins: session stopped", "There is not enough memory to receive the complete plugin snapshot. Your local channels and plugins were kept.");
cleanup:
    if (units) for (k = 0; k < INCOMING_UNIT_MAX; k++) if (units[k].path) { DeleteFileA(units[k].path); free(units[k].path); }
    free(units); free(tasks); free(keep);
}

// Errors that end the connection: status text + message box.
static const struct { const char *code, *status, *alert; } k_netErrors[] = {
    { "bad_password", "Wrong session password", "Wrong session password." },
    { "no_session", "Session not found",
      "That session isn't running.\n\nCheck the link, and ask the host whether they are still hosting." },
    { "full", "All sessions are in use", "All sessions on this server are in use right now.\n\nTry again later." },
    { "owner_required", "Server password needed",
      "This server needs its password to start a session.\n\nCtrl+click Host and enter it (whoever runs the server has it)." },
    { "in_use", "Session 00 is already running", "Session 00 is already running." },
    { "bad_owner", "Wrong owner key", "Wrong owner key." },
    { "too_many_attempts", "Too many wrong passwords",
      "Too many wrong passwords from this computer.\n\nWait 10 minutes, then try again." },
    { "id_in_use", "Already in this session", "You are already in this session (from another FL?)." },
    { "session_full", "Session is full", "That session already has 8 people." },
    { "too_many_connections", "Too many connections", "Too many flim connections from your network right now." },
    { "bad_request", "Bad session password", "The session password must be 1 to 128 characters." },
    { "idle", "Session closed: 5 minutes idle",
      "The session was closed after 5 minutes without activity.\n\nHost again to start a new one." },
};

static void compat_fail(const char *why);

static void net_server_error(const char *m) {
    FlJson envelope = {m, strlen(m)};
    char error_code[64] = ""; int i;
    fc_text(envelope, "code", error_code, sizeof(error_code));
    if (!strcmp(error_code, "compatibility")) {
        FlJson root = {m, strlen(m)}, value; char why[512];
        if (!fj_get(root, "msg", &value) || !fj_decode(value, why, sizeof(why)))
            strcpy_s(why, sizeof(why), "The relay refused an incompatible FL build or edit. Update flim on all computers and reconnect.");
        compat_fail(why); return;
    }
    if (g_compatReady) {
        FlJson root = {m, strlen(m)}, value;
        char why[512], code[48] = "";
        if (fj_get(root, "code", &value)) fj_text(value, code, sizeof(code));
        if (!fj_get(root, "msg", &value) || !fj_decode(value, why, sizeof(why)))
            strcpy_s(why, sizeof(why), "The relay rejected a request. Reconnect and resync before continuing to share.");
        sharing_fail(!strcmp(code, "storage_limit") || !strcmp(code, "r2_storage_limit") || !strcmp(code, "r2_monthly_limit") ?
            "File allowance reached: sharing stopped" : "Relay rejected an edit: sharing stopped", why);
        return;
    }
    uint32_t ms = 0;
    if ((jget_u32(m, "cooldown", &ms) || jget_u32(m, "retry_in", &ms)) && ms) g_coolUntil = GetTickCount64() + ms;
    if (!strcmp(error_code, "time_up")) {
        strcpy_s(g_netErr, sizeof(g_netErr), "Time's up: session ended");
        net_info("Time's up: this session's 15 minutes are over.\n\n"
                 "Everything you made stays in your FL. You can host or join a session again in 5 minutes.");
        return;
    }
    if (!strcmp(error_code, "cooldown")) {
        unsigned cs = cooldown_secs();
        strcpy_s(g_netErr, sizeof(g_netErr), "Cooldown");
        net_info("COOLDOWN: you can host or join a session again in %u:%02u.\n\n"
                 "After a session's time runs out, everyone in it waits 5 minutes, so others get a turn.", cs / 60, cs % 60);
        return;
    }
    for (i = 0; i < (int)(sizeof(k_netErrors) / sizeof(k_netErrors[0])); i++) {
        if (!strcmp(error_code, k_netErrors[i].code)) {
            strcpy_s(g_netErr, sizeof(g_netErr), k_netErrors[i].status);
            net_alert("%s", k_netErrors[i].alert);
            return;
        }
    }
}

// Hosting and welcomed: retain the invite for the user-initiated status action.
static void hosted_ready(void) {
    char link[400];
    session_link(&g_netUrl, g_session, link, sizeof(link));
    EnterCriticalSection(&g_netTextLock);
    sprintf_s(g_hostedText, sizeof(g_hostedText), "Session: %s\r\nLink: %s\r\nPassword: %s", g_session, link, g_hostPw);
    LeaveCriticalSection(&g_netTextLock);
    SecureZeroMemory(g_hostPw, sizeof(g_hostPw));
    logmsg("HOST room ready");
}

// Shut down the socket here; the receive thread owns queue/connection cleanup. Avoid
// clearing queues while the outbox holds its lock or the FL main thread is applying an op.
static void sharing_fail(const char *status, const char *why) {
    EnterCriticalSection(&g_sendLock);
    if (!session_current() || InterlockedCompareExchange(&g_compatFault, 1, 0)) { LeaveCriticalSection(&g_sendLock); return; }
    InterlockedExchange(&g_compatReady, 0);
    logmsg("SHARING stopped session: %s", why);
    strcpy_s(g_netErr, sizeof(g_netErr), status);
    net_alert("%.280s\n\nflim stopped sharing. Check your local project before reconnecting.", why);
    if (g_ws) WinHttpWebSocketShutdown(g_ws, WINHTTP_WEB_SOCKET_POLICY_VIOLATION_CLOSE_STATUS, NULL, 0);
    LeaveCriticalSection(&g_sendLock);
}
static void compat_fail(const char *why) { sharing_fail("FL build compatibility: session stopped", why); }
static void cloud_fail(const char *why) { sharing_fail("Cloudflare transfer: session stopped", why); }

static void blob_limit_error(DWORD status, const char *body) {
    FlJson root = {body, strlen(body)}, value;
    char code[48] = "";
    if (fj_get(root, "code", &value)) fj_text(value, code, sizeof(code));
    if (!strcmp(code, "r2_monthly_limit"))
        cloud_fail("The relay reached its monthly R2 operation allowance. File sharing is blocked until the next monthly reset.");
    else if (status == 507)
        cloud_fail("The relay reached its file storage allowance. The host must free space before file sharing can resume.");
    else cloud_fail("The relay reached its request allowance. Reconnect and resync after the allowance resets.");
}

static int compat_accept(const char *m) {
    FlJson root = {m, strlen(m)}, c, value;
    char host[32], wire[64], mine[32]; int mixed, notes = 0, portable = 0;
    if (fj_get(root, "portable_sync", &value)) {
        if (!fj_is(value, "1")) { compat_fail("The relay selected an unsupported portable sync protocol."); return 0; }
        portable = 1;
    }
    if (g_compatReady && portable != g_portableSync) { compat_fail("The room changed its project compatibility protocol. Reconnect before continuing."); return 0; }
    if (fj_get(root, "notes_crdt", &value)) {
        if (!fj_is(value, "1")) { compat_fail("The relay selected an unsupported note merge protocol."); return 0; }
        notes = 1;
    }
    if (g_compatReady && notes != g_notesCrdt) { compat_fail("The room changed its note merge protocol. Reconnect before continuing."); return 0; }
    if (!fj_get(root, "compatibility", &c) || !fj_get(c, "protocol", &value) || !fj_is(value, "1") ||
        !fj_get(c, "host_fl", &value) || !fj_text(value, host, sizeof(host)) || !flim_version_family(host) ||
        !fj_get(c, "wire", &value) || !fj_text(value, wire, sizeof(wire)) || strcmp(wire, FLIM_WIRE) ||
        !fj_get(c, "mixed", &value) || (!fj_is(value, "true") && !fj_is(value, "false")) ||
        !WideCharToMultiByte(CP_UTF8, 0, g_fl.build, -1, mine, 32, NULL, NULL) || !flim_version_family(mine)) {
        compat_fail("This server cannot verify FL 24/25/26 compatibility. Update the relay and every participant's flim client.");
        return 0;
    }
    mixed = fj_is(value, "true");
    if ((!portable && flim_version_cmp(host, mine) > 0) || (g_compatReady && strcmp(host, g_hostFlBuild)) ||
        (!mixed && strcmp(host, mine))) {
        compat_fail("The host must use the oldest FL build in the session. A newer host project cannot be loaded into an older FL.");
        return 0;
    }
    if (!session_current()) return 0;
    if (!g_compatReady) strcpy_s(g_hostFlBuild, sizeof(g_hostFlBuild), host);
    InterlockedExchange(&g_compatMixed, mixed);
    InterlockedExchange(&g_notesCrdt, notes);
    InterlockedExchange(&g_portableSync, portable);
    InterlockedExchange(&g_portableLocal, portable && flim_version_cmp(host, mine) > 0);
    InterlockedExchange(&g_compatReady, 1);
    logmsg("COMPAT protocol=1 host=%s local=%s mixed=%d wire=%s notes=%s", host, mine, mixed, wire, notes ? "CRDT-1" : "locked snapshots");
    return 1;
}

static int compat_plugin_send(void) {
    char mine[32];
    return g_portableSync || !g_compatMixed || (g_fl.build && WideCharToMultiByte(CP_UTF8, 0, g_fl.build, -1, mine, sizeof(mine), NULL, NULL) && !strcmp(mine, g_hostFlBuild));
}

static int compat_outgoing(const char *msg) {
    FlJson root = {msg, strlen(msg)}, value, op; char type[24], kind[65], mine[32];
    if (!fj_get(root, "t", &value) || !fj_text(value, type, sizeof(type))) return 0;
    if (strcmp(type, "op")) return 1;
    if (!g_compatReady || g_compatFault) return 0;
    if (!fj_get(root, "op", &op) || !fj_get(op, "kind", &value) || !fj_text(value, kind, sizeof(kind))) return 0;
    if (g_portableLocal && !strcmp(kind, "clips.set")) return 0;
    if (!g_compatMixed) return 1;
    if (!flim_wire_known(kind)) { compat_fail("This edit has no agreed format for mixed FL builds."); return 0; }
    if (!strcmp(kind, "plug.state") && !compat_plugin_send()) {
        logmsg("COMPAT withheld newer plugin preset; host must make this edit, room stays connected");
        return 0;
    }
    if (!g_portableSync && flim_wire_opaque(kind)) {
        if (!WideCharToMultiByte(CP_UTF8, 0, g_fl.build, -1, mine, 32, NULL, NULL) || strcmp(mine, g_hostFlBuild)) {
            compat_fail("Plugin replacement, preset changes and adding channels from a newer FL cannot be shared with an older FL. Ask the oldest-build host to make that edit.");
            return 0;
        }
    }
    return 1;
}

static int compat_incoming(const char *msg) {
    FlJson root = {msg, strlen(msg)}, value, op; char type[24], kind[65], source[32], mine[32];
    if (!session_current() || g_compatFault || !fj_get(root, "t", &value) || !fj_text(value, type, sizeof(type))) return 0;
    if (!strcmp(type, "welcome") || !strcmp(type, "presence")) return compat_accept(msg);
    if (strcmp(type, "op")) return 1;
    if (!g_compatReady || !fj_get(root, "source_fl", &value) || !fj_text(value, source, sizeof(source)) ||
        !flim_version_family(source) || !fj_get(root, "op", &op) || !fj_get(op, "kind", &value) ||
        !fj_text(value, kind, sizeof(kind))) {
        compat_fail("The relay sent an edit without a verified sender build."); return 0;
    }
    if (g_compatMixed && (!flim_wire_known(kind) || (!g_portableSync && flim_wire_opaque(kind) && strcmp(source, g_hostFlBuild)))) {
        compat_fail("The relay sent an edit that is incompatible with this mixed-build session."); return 0;
    }
    if (!g_portableSync && flim_wire_opaque(kind) &&
        (!WideCharToMultiByte(CP_UTF8, 0, g_fl.build, -1, mine, 32, NULL, NULL) || flim_version_cmp(source, mine) > 0)) {
        compat_fail("A newer FL project or plugin state cannot be loaded by this FL build."); return 0;
    }
    return 1;
}

static void on_chan_order(const char *m) {
    FlJson root = {m, strlen(m)}, op, value, from;
    uint64_t n, index;
    int order[MAX_CH + 1], count = 0;
    unsigned char seen[MAX_CH] = {0};
    const char *p, *end, *start;
    if (!fj_get(root, "op", &op) || !fj_get(op, "n", &value) || !fc_uint(value, &n) || !n || n > MAX_CH ||
        !fj_get(op, "from", &from) || from.n < 2 || from.p[0] != '[') goto invalid;
    p = from.p + 1; end = from.p + from.n - 1;
    fj_space(&p, end);
    while (p < end) {
        start = p;
        if (count >= (int)n || !fj_value(&p, end, 0)) goto invalid;
        value.p = start; value.n = (size_t)(p - start);
        if (!fc_uint(value, &index) || index >= n || seen[index]) goto invalid;
        seen[index] = 1; order[++count] = (int)index;
        fj_space(&p, end);
        if (p < end) { if (*p++ != ',') goto invalid; fj_space(&p, end); }
    }
    if (count != (int)n) goto invalid;
    { QItem q = {0}; size_t bytes = sizeof(int) * ((size_t)n + 1);
      order[0] = (int)n; q.type = T_ORDER; q.order = (int *)malloc(bytes);
      if (q.order) memcpy(q.order, order, bytes);
      enqueue(&q); }
    return;
invalid:
    sharing_fail("Shared channels: session stopped", "The shared channel order is incomplete or invalid. Reconnect and resync before continuing to share.");
}

static void handle_msg_inner(const char *m);
static void handle_msg(const char *m) {
    EnterCriticalSection(&g_lifecycleLock);
    if (session_current()) handle_msg_inner(m);
    LeaveCriticalSection(&g_lifecycleLock);
}

static void handle_msg_inner(const char *m) {
    uint32_t id, v;
    if (!compat_incoming(m)) return;
    int unit, a, b;
    char *path;
    FlJson root = {m, strlen(m)}, op = {0}, value;
    char target[65], source[32] = "", mine[32], type[24], kind[65] = "";
    int newer = 0;
    if (!fc_text(root, "t", type, sizeof(type))) return;
    if (!strcmp(type, "op") && (!fj_get(root, "op", &op) || !fc_text(op, "kind", kind, sizeof(kind)))) return;
    if (fj_get(root, "op", &op)) {
        if (fj_get(op, "for", &value) && (!fj_text(value, target, sizeof(target)) || strcmp(target, g_myId))) return;
        if (g_portableSync && fj_get(root, "source_fl", &value) && fj_text(value, source, sizeof(source)) &&
            WideCharToMultiByte(CP_UTF8, 0, g_fl.build, -1, mine, sizeof(mine), NULL, NULL)) {
            char original[32];
            if (fj_get(op, "preset_fl", &value)) {
                if (!fj_text(value, original, sizeof(original)) || !flim_version_family(original)) { sharing_fail("Shared plugin: sharing paused", "The retained preset's original FL build is invalid."); return; }
                if (flim_version_cmp(original, source) > 0) strcpy_s(source, sizeof(source), original);
            }
            newer = flim_version_cmp(source, mine) > 0;
        }
    }
    if (!strcmp(kind, "project.load")) {
        if (!g_isLeader) on_project_load(m);
        return;
    }
    if (hold_if_loading(m)) return;
    if (!strcmp(kind, "portable.start")) {
        uint64_t count;
        if (g_portableLocal && fj_get(op, "nch", &value) && fc_uint(value, &count) && count <= MAX_CH)
            enqueue_unit(T_PORTABLESTART, 0, (int)count, 0, 0, NULL);
        else if (g_portableLocal) sharing_fail("Portable sync: sharing paused", "The shared channel count is invalid. Your local project was kept.");
    } else if (!strcmp(kind, "state.req")) {
        // join / member re-sync: send the project (mid-load, the load's own broadcast covers it)
        if (g_isLeader && !g_projBusy) {
            if (g_portableSync && fj_get(op, "portable", &value) && fj_is(value, "1") &&
                fj_get(root, "from", &value) && fj_text(value, target, sizeof(target)) && peer_id_valid(target))
                enqueue_unit(T_PORTABLESEND, 0, 0, 0, 0, _strdup(target));
            else enqueue_unit(T_PROJSNAP, 0, 0, 0, 0, NULL);
        }
    } else if (!strcmp(kind, "plug.full")) {
        if (!g_isLeader && !newer) apply_plug_full(m);
    } else if (!strcmp(kind, "plug.state")) {
        if (parse_unit(m, &unit, &a, &b, &path) && path) { QItem load = {0}; load.type = T_LOAD; load.unit = unit; load.a = a; load.b = b; load.mode = newer ? 3 : 0; load.path = path; strcpy_s(load.presetFl, sizeof(load.presetFl), source); enqueue(&load); }
    } else if (!strcmp(kind, "chan.add")) {
        if (parse_unit(m, &unit, &a, &b, &path) && path) { QItem load = {0}; load.type = T_ADDCH; load.unit = U_CH; load.a = a; load.mode = newer ? 3 : 0; load.path = path; strcpy_s(load.presetFl, sizeof(load.presetFl), source); enqueue(&load); }
    } else if (!strcmp(kind, "chan.del")) {
        if (fj_get(op, "ch", &value) && fj_u32(value, &id) && id < MAX_CH) enqueue_unit(T_DELCH, U_CH, (int)id, 0, 0, NULL);
        else sharing_fail("Shared channel: sharing paused", "The channel deletion target is invalid. Your channels were kept.");
    } else if (!strcmp(kind, "notes.set")) {
        on_notes(m, 0);
    } else if (!strcmp(kind, "clips.set")) {
        if (!g_portableLocal) on_clips_set(m);
    } else if (!strcmp(kind, "meta.set")) {
        on_meta_set(m);
    } else if (!strcmp(kind, "pat.op")) {
        on_pat_op(m);
    } else if (!strcmp(kind, "focus")) {
        on_focus(m);
    } else if (!strcmp(kind, "cur")) {
        on_cursor(m);
    } else if (!strcmp(kind, "notes.full")) {
        if (!g_isLeader) on_notes(m, 1);
    } else if (!strcmp(kind, "fx.clear")) {
        if (fj_get(op, "trk", &value) && fj_u32(value, &id) && id < MAX_MIX &&
            fj_get(op, "slot", &value) && fj_u32(value, &v) && v < MAX_FX_SLOTS)
            enqueue_unit(T_FXCLEAR, U_FX, (int)id, (int)v, 0, NULL);
        else sharing_fail("Shared effect: sharing paused", "The effect deletion target is invalid. Your effects were kept.");
    } else if (!strcmp(kind, "chan.order")) {
        on_chan_order(m);
    } else if (!strcmp(kind, "state.full")) {
        if (!g_isLeader) apply_full_state(m);
    } else if (!strcmp(type, "welcome")) {
        char acceptedSession[FLIM_SESSION_CAP];
        if (!welcome_session(m, &g_netUrl, acceptedSession)) {
            cloud_fail("The relay returned an invalid room. Reconnect using the room link from the desktop app.");
            return;
        }
        { FlJson root = { m, strlen(m) }, value;
          InterlockedExchange(&g_cloudTransport, fj_get(root, "transport", &value) && fj_is(value, "2")); }
        if (g_cloudTransport) logmsg("CLOUD file transport negotiated");
        strncpy_s(g_peersJson, sizeof(g_peersJson), m, _TRUNCATE);
        logmsg("NET welcome accepted (transport=%ld)", g_cloudTransport);
        if (!fj_get(root, "role", &value) || (!fj_is(value, "\"leader\"") && !fj_is(value, "\"member\""))) {
            sharing_fail("Room role: sharing paused", "The relay did not provide a valid room role. Reconnect before sharing."); return;
        }
        g_isLeader = fj_is(value, "\"leader\"");
        if (g_notesCrdt) enqueue_unit(T_NOTEBASE, 0, 0, 0, 0, NULL);
        {   // the room identity and its private sample-store key
            FlJson root = { m, strlen(m) }, value;
            char blob[65];
            strcpy_s(g_session, sizeof(g_session), acceptedSession);
            sprintf_s(g_netShown, sizeof(g_netShown), "%s/%s%s", g_netRoot,
                      strlen(g_session) == 8 ? "room/" : "", g_session);
            if (fj_get(root, "blob", &value) && fj_text(value, blob, sizeof(blob)) && strlen(blob) == 64) samples_key(blob);
            SecureZeroMemory(blob, sizeof(blob));
        }
        peer_welcome(m);
        {   // time limit: counted down in the bar; members get the note now, the host in the hosted dialog
            uint32_t ms = 0;
            jget_u32(m, "ends_in", &ms);
            g_endsAt = ms ? GetTickCount64() + ms : 0;
            if (ms && !g_hosting) net_info("%s", LIMIT_TEXT);
        }
        if (g_hosting && g_isLeader) hosted_ready();
        net_show_connected(m);
        if (!g_isLeader) request_state();
    } else if (!strcmp(type, "op")) {
        if ((!strcmp(kind, "param.set")) && fj_get(op, "id", &value) && fj_u32(value, &id) && fj_get(op, "v", &value) && fj_u32(value, &v)) {
            if (!param_id_with_limit(id, MAX_MIX)) sharing_fail("Shared control: sharing paused", "The incoming control target is invalid. Your local controls were kept.");
            else route_inbound(id, v, 0);
        } else if (!strcmp(kind, "param.set")) sharing_fail("Shared control: sharing paused", "The incoming control value is invalid. Your local controls were kept.");
    } else if ((!strcmp(type, "lock") || !strcmp(type, "lock_released")) && on_unit_lock(m)) {
        // pattern / playlist lock (mutexing)
    } else if (!strcmp(type, "lock") && jget_paramkey(m, &id)) {
        Slot *s = slot_by_id(id);
        char owner[64]; int granted, mine;
        if (!fj_get(root, "granted", &value) || (!fj_is(value, "true") && !fj_is(value, "false")) ||
            !fc_text(root, "owner", owner, sizeof(owner)) || !peer_id_valid(owner)) return;
        granted = fj_is(value, "true"); mine = !strcmp(owner, g_myId);
        if (s) {
            if (granted && !mine) s->lockedByPeer = 1;
            if (!granted && !mine) { s->lockedByMe = 0; s->lockedByPeer = 1; logmsg("lock denied id=0x%08x", id); }
        }
    } else if (!strcmp(type, "lock_released") && jget_paramkey(m, &id)) {
        Slot *s = slot_by_id(id);
        if (s) s->lockedByPeer = 0;
    } else if (!strcmp(type, "presence")) {
        strncpy_s(g_peersJson, sizeof(g_peersJson), m, _TRUNCATE);
        InterlockedExchange(&g_focusResend, 1);           // a newcomer: tell them where we are
        logmsg("NET room presence updated");
        net_show_connected(m);
    } else if (!strcmp(type, "error")) {
        {
            FlJson root = {m, strlen(m)}, value;
            char code[64] = "unknown"; size_t k;
            if (fj_get(root, "code", &value) && fj_text(value, code, sizeof(code)))
                for (k = 0; code[k]; k++) if (!isalnum((unsigned char)code[k]) && code[k] != '_') { strcpy_s(code, sizeof(code), "invalid"); break; }
            logmsg("NET relay error code=%s", code);
        }
        net_server_error(m);
    } else if (!strcmp(type, "leader_left")) {
        logmsg("NET host left the room");
        strcpy_s(g_netErr, sizeof(g_netErr), "The host left: session ended");
        net_alert("The host left: the session ended.");
    }
}

// ---------------- samples ----------------
// Sample files travel with the data that uses them. FLP event 196 (a channel's sample path,
// UTF-16) appears in .flp files and in saved channel states alike, so the same code covers
// project loads (project.load) and live channel changes (plug.state / chan.add).
// Sender (outbox thread): the op lists the samples its data references,
//   "samples":[{"p":<base64 UTF-16 path as written in the data>,"h":<sha256 hex>,"s":<bytes>}],
// after uploading the files the server doesn't have yet to its blob store (HTTP next to the
// WebSocket: /blobs/missing, /blob/<sha256>; see server/src/blobs.ts). More than
// SAMPLE_ASK_BYTES to upload at once -> Yes/No dialog first; "No" leaves those samples out
// (and they are not asked about again this session). Every op queued behind waits, so the
// order of ops is kept.
// Receiver (inbox thread): before an op that lists samples is handled, each sample is found
// locally (same path with the same content, or any file known to have that content) or
// downloaded into Documents\flim\samples\<hash>\; the paths in the op's data are then rewritten
// to the local files. Later ops wait behind it, again to keep the order.
// Samples inside plugin states (event 213, the plugin's own data) travel the same way: paths
// are found in Image-Line's tag/length/value layout (FPC and other newer IL plugins; rewritten
// with every enclosing length fixed), and as plain absolute UTF-16 / ANSI paths anywhere else in
// the data (any other plugin). Those get a local alias of exactly the same length (a hard link
// to the downloaded file), so length fields inside a format we don't know stay valid.
// Compressed / encrypted states (Kontakt...) show no paths and are left as they are.
#define EV_SAMPLE_PATH   196
#define EV_PLUGIN_DATA   213
#define SAMPLE_ASK_BYTES (50ull * 1024 * 1024)
#define SAMPLE_MAX_BYTES (2000ull * 1024 * 1024)
#define SAMPLE_PATH_MAX  1024
#define BLOB_CHUNK       (256 * 1024)

typedef struct { wchar_t *path; uint64_t size; FILETIME mt; char hex[65]; LONG peerGen; } HashEnt;
typedef struct { wchar_t *from, *to; } PathMap;
typedef struct OutItem { LONG gen; char *msg; unsigned char *blob; size_t blobn, bytes; struct OutItem *next; } OutItem;
typedef struct InItem { LONG gen; char *msg; size_t bytes; struct InItem *next; } InItem;
#define TRANSFER_QUEUE_MAX_COUNT 4096
#define TRANSFER_QUEUE_MAX_BYTES (128u * 1024u * 1024u)

static HashEnt *g_hashes;  static int g_nhash, g_caphash;    // content hash per local file (path+size+mtime)
#define HASH_CACHE_MAX 8192
static unsigned g_hashEvict;
static PathMap *g_pmap;    static int g_npmap, g_cappmap;    // receiver: path in peer data -> local file
static char (*g_declined)[65]; static int g_ndeclined, g_capdeclined;   // "No" in the upload dialog
static CRITICAL_SECTION g_sampleLock, g_outLock, g_inLock;                        // all of the above + the blob server address
static NetUrl  g_blobUrl;
static char    g_blobKey[65];                                // the session's sample store key (welcome)
static volatile LONG g_blobOn = 0;
static int     g_noLocal = 0;                                // FLIM_SAMPLE_NOLOCAL=1 (tests): ignore local copies
static OutItem *g_outHead, *g_outTail;
static int     g_outBusy;
static size_t  g_outBytes, g_outCount;
static InItem  *g_inHead, *g_inTail;
static int     g_inBusy;
static size_t  g_inBytes, g_inCount;
static HANDLE  g_outEvt, g_inEvt;
static __declspec(thread) uint64_t g_xferDone, g_xferTotal;
static __declspec(thread) const char *g_xferWhat = "";
static __declspec(thread) DWORD g_xferShown;

typedef struct { BCRYPT_ALG_HANDLE alg; BCRYPT_HASH_HANDLE h; } Sha;
static int sha_begin(Sha *s) {
    memset(s, 0, sizeof(*s));
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&s->alg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) return 0;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(s->alg, &s->h, NULL, 0, NULL, 0, 0))) { BCryptCloseAlgorithmProvider(s->alg, 0); return 0; }
    return 1;
}
static int sha_add(Sha *s, const void *p, size_t n) { return n <= ULONG_MAX && BCRYPT_SUCCESS(BCryptHashData(s->h, (PUCHAR)p, (ULONG)n, 0)); }
static int sha_end(Sha *s, char hex[65]) {
    UCHAR d[32];
    int i, ok = BCRYPT_SUCCESS(BCryptFinishHash(s->h, d, 32, 0));
    hex[0] = 0;
    BCryptDestroyHash(s->h);
    BCryptCloseAlgorithmProvider(s->alg, 0);
    if (ok) for (i = 0; i < 32; i++) sprintf_s(hex + i * 2, 3, "%02x", d[i]);
    return ok;
}
static int sha_hex(const void *p, size_t n, char hex[65]) {
    Sha s; UCHAR d[32]; int i, ok;
    hex[0] = 0;
    if (!sha_begin(&s)) return 0;
    ok = BCRYPT_SUCCESS(BCryptHashData(s.h, (PUCHAR)p, (ULONG)n, 0)) && BCRYPT_SUCCESS(BCryptFinishHash(s.h, d, 32, 0));
    BCryptDestroyHash(s.h); BCryptCloseAlgorithmProvider(s.alg, 0);
    if (!ok) return 0;
    for (i = 0; i < 32; i++) sprintf_s(hex + i * 2, 3, "%02x", d[i]);
    return 1;
}
static int is_hex64(const char *h) {
    int i;
    for (i = 0; i < 64; i++) if (!((h[i] >= '0' && h[i] <= '9') || (h[i] >= 'a' && h[i] <= 'f'))) return 0;
    return 1;
}

// Transfer progress in the toolbar status.
static void xfer_show(int force) {
    DWORD now = GetTickCount();
    if (!force && now - g_xferShown < 1000) return;
    g_xferShown = now;
    net_status(NET_ON, "%s samples: %.1f / %.1f MB", g_xferWhat, g_xferDone / 1048576.0, g_xferTotal / 1048576.0);
}
static void xfer_end(void) { if (g_peersJson[0]) net_show_connected(g_peersJson); }

static int file_info(const wchar_t *p, uint64_t *size, FILETIME *mt) {
    WIN32_FILE_ATTRIBUTE_DATA a;
    if (!GetFileAttributesExW(p, GetFileExInfoStandard, &a) || (a.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) return 0;
    *size = ((uint64_t)a.nFileSizeHigh << 32) | a.nFileSizeLow;
    if (mt) *mt = a.ftLastWriteTime;
    return 1;
}
static int is_abs_path(const wchar_t *p) {
    return (iswalpha(p[0]) && p[1] == L':' && (p[2] == L'\\' || p[2] == L'/')) || (p[0] == L'\\' && p[1] == L'\\');
}

static int hash_file(const wchar_t *p, char hex[65]) {
    hex[0] = 0;
    HANDLE f = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    unsigned char *buf;
    DWORD got;
    Sha s;
    int ok = 1;
    if (f == INVALID_HANDLE_VALUE) return 0;
    if (!sha_begin(&s)) { CloseHandle(f); return 0; }
    buf = (unsigned char *)malloc(BLOB_CHUNK * 4);
    if (!buf) { sha_end(&s, hex); hex[0] = 0; CloseHandle(f); return 0; }
    for (;;) {
        if (!session_current()) { ok = 0; break; }
        if (!ReadFile(f, buf, BLOB_CHUNK * 4, &got, NULL)) { ok = 0; break; }
        if (!got) break;
        if (!sha_add(&s, buf, got)) { ok = 0; break; }
    }
    if (!sha_end(&s, hex)) ok = 0;
    free(buf);
    CloseHandle(f);
    if (!ok) hex[0] = 0;
    return ok;
}

static void hash_put(const wchar_t *p, uint64_t size, FILETIME mt, const char *hex) {
    int i;
    EnterCriticalSection(&g_sampleLock);
    for (i = 0; i < g_nhash && _wcsicmp(g_hashes[i].path, p) != 0; i++) {}
    if (i == g_nhash) {
        wchar_t *copy = _wcsdup(p);
        if (!copy) { LeaveCriticalSection(&g_sampleLock); return; }
        if (g_nhash == HASH_CACHE_MAX) {
            i = (int)(g_hashEvict++ % HASH_CACHE_MAX);
            free(g_hashes[i].path); g_hashes[i].path = copy;
            g_hashes[i].peerGen = 0;
        } else {
            if (g_nhash == g_caphash) {
                int cap = g_caphash ? g_caphash * 2 : 256;
                HashEnt *entries = (HashEnt *)realloc(g_hashes, sizeof(HashEnt) * cap);
                if (!entries) { free(copy); LeaveCriticalSection(&g_sampleLock); return; }
                g_hashes = entries; g_caphash = cap;
            }
            g_hashes[g_nhash].peerGen = 0; g_hashes[g_nhash++].path = copy;
        }
    } else if (g_hashes[i].size != size || CompareFileTime(&g_hashes[i].mt, &mt) || strcmp(g_hashes[i].hex, hex)) g_hashes[i].peerGen = 0;
    g_hashes[i].size = size; g_hashes[i].mt = mt;
    strcpy_s(g_hashes[i].hex, sizeof(g_hashes[i].hex), hex);
    LeaveCriticalSection(&g_sampleLock);
}

// Content hash of a local file (cached while path, size and mtime stay the same).
static int sample_hash(const wchar_t *p, char hex[65], uint64_t *size) {
    FILETIME mt;
    uint64_t sz;
    int i, hit = 0;
    hex[0] = 0; *size = 0;
    if (!session_current() || !file_info(p, &sz, &mt) || !sz || sz > SAMPLE_MAX_BYTES) return 0;
    EnterCriticalSection(&g_sampleLock);
    for (i = 0; i < g_nhash; i++)
        if (_wcsicmp(g_hashes[i].path, p) == 0 && g_hashes[i].size == sz && CompareFileTime(&g_hashes[i].mt, &mt) == 0) {
            strcpy_s(hex, 65, g_hashes[i].hex); hit = 1; break;
        }
    LeaveCriticalSection(&g_sampleLock);
    if (!hit) {
        FILETIME after; uint64_t afterSize;
        if (!hash_file(p, hex)) return 0;
        if (!file_info(p, &afterSize, &after) || afterSize != sz || CompareFileTime(&after, &mt) || !session_current()) {hex[0] = 0; return 0;}
        hash_put(p, sz, mt, hex);
    }
    *size = sz;
    return 1;
}

// Any local file known to have this content (and unchanged since it was hashed).
static int find_by_hash(const char *hex, wchar_t *out, int cap) {
    int i = 0;
    if (cap <= 0) return 0;
    out[0] = 0;
    for (;;) {
        if (!session_current()) return 0;
        wchar_t *path = NULL; uint64_t expected = 0, sz; FILETIME mt, expectedMt;
        EnterCriticalSection(&g_sampleLock);
        while (i < g_nhash) {
            HashEnt *entry = &g_hashes[i++];
            if (strcmp(entry->hex, hex)) continue;
            path = _wcsdup(entry->path); expected = entry->size; expectedMt = entry->mt; break;
        }
        LeaveCriticalSection(&g_sampleLock);
        if (!path) return 0;
        if (wcslen(path) < (size_t)cap && file_info(path, &sz, &mt) && sz == expected && !CompareFileTime(&mt, &expectedMt)) {
            wcscpy_s(out, cap, path); free(path); return 1;
        }
        free(path);
    }
}

static void map_set(const wchar_t *from, const wchar_t *to) {
    int i, failed = 0;
    EnterCriticalSection(&g_sampleLock);
    if (!session_current()) { LeaveCriticalSection(&g_sampleLock); return; }
    for (i = 0; i < g_npmap && _wcsicmp(g_pmap[i].from, from) != 0; i++) {}
    if (!to) {
        if (i < g_npmap) { free(g_pmap[i].from); free(g_pmap[i].to); g_pmap[i] = g_pmap[--g_npmap]; }
    } else {
        wchar_t *target = _wcsdup(to), *source = i == g_npmap ? _wcsdup(from) : NULL;
        if (!target || (i == g_npmap && !source)) failed = 1;
        if (i == g_npmap && g_npmap >= SAMPLE_PATH_MAX * 8) failed = 1;
        if (!failed && i == g_npmap && g_npmap == g_cappmap) {
            int cap = g_cappmap ? g_cappmap * 2 : 64;
            PathMap *entries = (PathMap *)realloc(g_pmap, sizeof(PathMap) * cap);
            if (!entries) failed = 1;
            else { g_pmap = entries; g_cappmap = cap; }
        }
        if (failed) { free(target); free(source); }
        else {
            if (i == g_npmap) { g_pmap[g_npmap].from = source; g_pmap[g_npmap++].to = NULL; }
            free(g_pmap[i].to); g_pmap[i].to = target;
        }
    }
    LeaveCriticalSection(&g_sampleLock);
    if (failed) sharing_fail("Sample paths: session stopped", "There is not enough memory to map the shared samples to local files. Existing sample paths were kept.");
}

static int declined(const char *hex) {
    int i, r = 0;
    EnterCriticalSection(&g_sampleLock);
    for (i = 0; i < g_ndeclined && !r; i++) r = strcmp(g_declined[i], hex) == 0;
    LeaveCriticalSection(&g_sampleLock);
    return r;
}
static void decline(const char *hex) {
    int i, failed = 0;
    EnterCriticalSection(&g_sampleLock);
    if (!session_current()) { LeaveCriticalSection(&g_sampleLock); return; }
    for (i = 0; i < g_ndeclined && strcmp(g_declined[i], hex); i++) {}
    if (i == g_ndeclined) {
        if (g_ndeclined >= TRANSFER_QUEUE_MAX_COUNT) failed = 1;
        else if (g_ndeclined == g_capdeclined) {
            int cap = g_capdeclined ? g_capdeclined * 2 : 64;
            char (*next)[65] = (char (*)[65])realloc(g_declined, 65 * (size_t)cap);
            if (!next) failed = 1;
            else { g_declined = next; g_capdeclined = cap; }
        }
        if (!failed) strcpy_s(g_declined[g_ndeclined++], 65, hex);
    }
    LeaveCriticalSection(&g_sampleLock);
    if (failed) sharing_fail("Sample list: session stopped", "The declined-sample list exceeded its limit or available memory. Reconnect before continuing to share.");
}

static int sample_path_join(wchar_t *out, int cap, const wchar_t *tail) {
    size_t n = wcslen(out), add;
    int separator;
    while (*tail == L'\\' || *tail == L'/') tail++;
    add = wcslen(tail);
    separator = add && n && out[n - 1] != L'\\' && out[n - 1] != L'/';
    if (n + separator + add >= (size_t)cap) { out[0] = 0; return 0; }
    if (separator) out[n++] = L'\\';
    memcpy(out + n, tail, (add + 1) * sizeof(wchar_t));
    return 1;
}

// FL can resave downloaded samples under %ILSharedData%, using this root without "FL Studio".
static int fl_shared_data(wchar_t *out, int cap) {
    DWORD n;
    LSTATUS status;
    if (cap <= 0) return 0;
    out[0] = 0;
    n = (DWORD)cap * sizeof(wchar_t);
    status = RegGetValueW(HKEY_CURRENT_USER, L"Software\\Image-Line\\Shared\\Paths", L"Shared data",
                         RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_ZEROONFAILURE, NULL, out, &n);
    if (status == ERROR_MORE_DATA) return 0;
    if (status != ERROR_SUCCESS || !out[0]) {
        DWORD k = GetEnvironmentVariableW(L"USERPROFILE", out, cap);
        if (!k || k >= (DWORD)cap) { out[0] = 0; return 0; }
        if (!sample_path_join(out, cap, L"Documents\\Image-Line")) return 0;
    }
    return is_abs_path(out);
}

static int fl_user_data(wchar_t *out, int cap) {
    return fl_shared_data(out, cap) && sample_path_join(out, cap, L"FL Studio");
}

typedef struct { unsigned char id[16]; int format, unit; char *path; } PluginEntry;
static PluginEntry *g_pluginCatalog;
static size_t g_pluginCatalogN, g_pluginCatalogCap;
static int g_pluginCatalogRead;
static unsigned g_pluginCatalogFormats[2][2];
static uint64_t g_pluginCatalogStamp;

static uint64_t plugin_catalog_stamp(void) {
    static const wchar_t *const folders[] = {L"Generators\\VST", L"Generators\\VST3", L"Effects\\VST", L"Effects\\VST3"};
    wchar_t root[4096], query[4096];
    uint64_t stamp = 1; int folder;
    if (!fl_user_data(root, 4096) || !sample_path_join(root, 4096, L"Presets\\Plugin database\\Installed")) return stamp;
    for (folder = 0; folder < 4; folder++) {
        WIN32_FIND_DATAW fd; HANDLE found; unsigned count = 0;
        _snwprintf_s(query, 4096, _TRUNCATE, L"%s\\%s\\*.fst", root, folders[folder]);
        found = FindFirstFileW(query, &fd);
        if (found == INVALID_HANDLE_VALUE) continue;
        do {
            uint64_t entry;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            entry = state_hash((unsigned char *)fd.cFileName, wcslen(fd.cFileName) * sizeof(wchar_t));
            entry ^= ((uint64_t)fd.ftLastWriteTime.dwHighDateTime << 32) | fd.ftLastWriteTime.dwLowDateTime;
            entry ^= ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            stamp += entry ^ ((uint64_t)folder << 60);
        } while (++count < 8192 && FindNextFileW(found, &fd));
        FindClose(found);
    }
    return stamp;
}

static void plugin_catalog_clear(void) {
    size_t i;
    for (i = 0; i < g_pluginCatalogN; i++) free(g_pluginCatalog[i].path);
    free(g_pluginCatalog); g_pluginCatalog = NULL; g_pluginCatalogN = g_pluginCatalogCap = 0;
    memset(g_pluginCatalogFormats, 0, sizeof(g_pluginCatalogFormats));
    g_pluginCatalogRead = 0;
}

/* Main thread only; the Installed database is FL's scan result, not a guessed VST folder. */
static void plugin_catalog_read(void) {
    static const wchar_t *const folders[] = {L"Generators\\VST", L"Generators\\VST3", L"Effects\\VST", L"Effects\\VST3"};
    wchar_t root[4096];
    int folder, reliable = 1;
    if (g_pluginCatalogRead) return;
    g_pluginCatalogRead = 1;
    g_pluginCatalogStamp = plugin_catalog_stamp();
    if (!fl_user_data(root, 4096) || !sample_path_join(root, 4096, L"Presets\\Plugin database\\Installed")) return;
    for (folder = 0; folder < 4; folder++) {
        wchar_t query[4096], file[4096];
        WIN32_FIND_DATAW fd;
        HANDLE found;
        _snwprintf_s(query, 4096, _TRUNCATE, L"%s\\%s\\*.fst", root, folders[folder]);
        found = FindFirstFileW(query, &fd);
        if (found == INVALID_HANDLE_VALUE) continue;
        do {
            FILE *f = NULL;
            unsigned char *d;
            size_t size, got;
            FlimPlugin s;
            PluginEntry *next;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY || fd.nFileSizeHigh || !fd.nFileSizeLow || fd.nFileSizeLow > 256 * 1024) continue;
            size = fd.nFileSizeLow;
            _snwprintf_s(file, 4096, _TRUNCATE, L"%s\\%s\\%s", root, folders[folder], fd.cFileName);
            if (_wfopen_s(&f, file, L"rb") || !f) { reliable = 0; continue; }
            d = (unsigned char *)malloc(size);
            got = d ? fread(d, 1, size, f) : 0; fclose(f);
            if (!d || got != size) { reliable = 0; free(d); continue; }
            if (!flim_plugin_read(d, size, &s)) { free(d); continue; }
            free(d);
            if (g_pluginCatalogN >= 8192) { reliable = 0; break; }
            if (g_pluginCatalogN == g_pluginCatalogCap) {
                size_t cap = g_pluginCatalogCap + 256;
                next = (PluginEntry *)realloc(g_pluginCatalog, cap * sizeof(*next));
                if (!next) { reliable = 0; continue; }
                g_pluginCatalog = next; g_pluginCatalogCap = cap;
            }
            next = g_pluginCatalog + g_pluginCatalogN;
            next->path = _strdup(s.path);
            if (!next->path) { reliable = 0; continue; }
            memcpy(next->id, s.id, sizeof(s.id)); next->format = s.format; next->unit = folder / 2;
            g_pluginCatalogN++;
            g_pluginCatalogFormats[folder / 2][s.format - 2]++;
        } while (FindNextFileW(found, &fd));
        FindClose(found);
    }
    if (!reliable) memset(g_pluginCatalogFormats, 0, sizeof(g_pluginCatalogFormats));
    logmsg("PLUGIN catalog cached %zu scanned installations", g_pluginCatalogN);
}

static int plugin_local_file(const char *path) {
    DWORD attr;
    /* Only scanned absolute drive paths are eligible. UNC paths never trigger a network probe. */
    if (!path[0] || !isalpha((unsigned char)path[0]) || path[1] != ':' || (path[2] != '\\' && path[2] != '/')) return 0;
    attr = GetFileAttributesA(path);
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

static int plugin_path_same(const char *a, const char *b) {
    char first[4096], second[4096]; DWORD x, y; size_t i;
    if (!a[0] || !b[0]) return !strcmp(a, b);
    x = GetFullPathNameA(a, sizeof(first), first, NULL);
    y = GetFullPathNameA(b, sizeof(second), second, NULL);
    if (!x || x >= sizeof(first) || !y || y >= sizeof(second)) return !_stricmp(a, b);
    for (i = 0; first[i]; i++) if (first[i] == '/') first[i] = '\\';
    for (i = 0; second[i]; i++) if (second[i] == '/') second[i] = '\\';
    return !_stricmp(first, second);
}

static uint64_t plugin_retry_stamp(const unsigned char *d, size_t n, int unit) {
    FlimPlugin s; size_t i; uint64_t stamp = 1;
    if (!flim_plugin_read(d, n, &s)) return 0;
    for (i = 0; i < g_pluginCatalogN; i++) {
        const PluginEntry *e = &g_pluginCatalog[i]; WIN32_FILE_ATTRIBUTE_DATA attr; uint64_t entry;
        if (e->unit != unit || e->format != s.format || memcmp(e->id, s.id, s.format == 2 ? 4 : 16)) continue;
        entry = state_hash((const unsigned char *)e->path, strlen(e->path));
        if (plugin_local_file(e->path) && GetFileAttributesExA(e->path, GetFileExInfoStandard, &attr)) {
            entry ^= ((uint64_t)attr.ftLastWriteTime.dwHighDateTime << 32) | attr.ftLastWriteTime.dwLowDateTime;
            entry ^= ((uint64_t)attr.nFileSizeHigh << 32) | attr.nFileSizeLow;
        }
        stamp += entry;
    }
    return stamp;
}

static int plugin_prepare(const unsigned char *d, size_t n, int unit, unsigned char **local, size_t *localn, char *reason, size_t cap) {
    FlimPlugin s;
    const char *candidate = NULL, *exact = NULL;
    size_t i;
    int ambiguous = 0, unresolved = 0;
    *local = NULL; *localn = 0;
    if (!flim_plugin_read(d, n, &s)) {
        if ((n >= 4 && !memcmp(d, "FLhd", 4) && !flp_walk(d, n, NULL, NULL)) ||
            (s.wrappers == 1 && s.states == 1 && s.invalid)) {
            strcpy_s(reason, cap, "Malformed or unsupported wrapper preset; it was not passed to FL's loader");
            return 0;
        }
        return 1;
    }
    sprintf_s(reason, cap, "%.180s (VST%d)", s.name[0] ? s.name : "Unnamed plugin", s.format);
    plugin_catalog_read();
    for (i = 0; i < g_pluginCatalogN; i++) {
        const PluginEntry *e = &g_pluginCatalog[i];
        if (e->unit != unit || e->format != s.format || memcmp(e->id, s.id, s.format == 2 ? 4 : 16)) continue;
        if (!e->path[0]) { unresolved = 1; continue; } // Some FL scan records carry an ID without a path.
        if (!plugin_local_file(e->path)) continue;
        if (plugin_path_same(e->path, s.path)) exact = e->path;
        if (candidate && !plugin_path_same(candidate, e->path)) ambiguous = 1;
        if (!candidate) candidate = e->path;
    }
    if (exact) candidate = exact;
    else if (ambiguous) { strcat_s(reason, cap, ": several local binaries share this ID; scan only the intended installation"); return 0; }
    if (!candidate) {
        if (unresolved || !g_pluginCatalogFormats[unit][s.format - 2]) return 1; // Unknown catalog: let FL resolve by ID.
        strcat_s(reason, cap, ": matching ID not present in the scanned local database");
        return 0;
    }
    if (plugin_path_same(candidate, s.path)) return 1;
    *local = flim_plugin_path(d, n, candidate, FLIM_CLOUD_MAX, localn);
    if (!*local) return -1;
    logmsg("PLUGIN local VST%d path selected by stable ID: %.180s", s.format, s.name);
    return 1;
}

static void plugins_retry(void) {
    int i, attempted = 0;
    uint64_t stamp = plugin_catalog_stamp();
    if (stamp != g_pluginCatalogStamp) plugin_catalog_clear();
    plugin_catalog_read();
    for (i = 0; i < MAX_CH + MAX_MIX * MAX_FX_SLOTS; i++) {
        int unit = i < MAX_CH ? U_CH : U_FX;
        int a = i < MAX_CH ? i : (i - MAX_CH) / MAX_FX_SLOTS, b = i < MAX_CH ? 0 : (i - MAX_CH) % MAX_FX_SLOTS;
        Unit *u = unit_ptr(unit, a, b);
        if (u && u->unavailable == 1) {
            size_t n;
            unsigned char *d = plug_agreed_copy(unit, a, b, &n);
            uint64_t current = d ? plugin_retry_stamp(d, n, unit) : 0;
            char *path;
            if (!current || current == u->retryStamp || attempted) { free(d); continue; }
            path = tmp_path("pr");
            FILE *f = NULL;
            int ok = 0;
            if (path && !fopen_s(&f, path, "wb") && f) {
                ok = fwrite(d, 1, n, f) == n;
                if (fclose(f)) ok = 0;
            }
            free(d);
            if (!ok) {
                if (path) { DeleteFileA(path); free(path); }
                logmsg("PLUGIN retry deferred: retained state could not be written for %d %d/%d", unit, a, b);
                continue;
            }
            { QItem load = {0}; load.unit = unit; load.a = a; load.b = b; load.mode = 2; load.path = path;
              logmsg("PLUGIN automatic recovery: local installation changed for %d %d/%d", unit, a, b);
              do_load(&load); DeleteFileA(path); free(path); attempted = 1; }
        }
    }
}

static void plugins_auto_tick(DWORD now) {
    static DWORD last;
    if (!g_pluginRetryable || !g_compatReady || g_compatFault || g_projBusy || closing_now()) return;
    if (last && now - last < 5000) return;
    last = now;
    enqueue_unit(T_PLUGRETRY, 0, 0, 0, 0, NULL);
}
// A sample path as FL writes it -> a local file path. 0 = not a transferable file
// (factory data and other FL placeholders: every install has those).
static int expand_path(const wchar_t *p, wchar_t *out, int cap) {
    static const wchar_t UD[] = L"%FLStudioUserData%";
    static const wchar_t SD[] = L"%ILSharedData%";
    size_t ul;
    if (cap <= 0) return 0;
    if (p[0] != L'%') { if (wcslen(p) >= (size_t)cap) return 0; wcscpy_s(out, cap, p); return is_abs_path(out); }
    if (_wcsnicmp(p, UD, wcslen(UD)) == 0) {
        ul = wcslen(UD);
        if (!fl_user_data(out, cap)) return 0;
    } else if (_wcsnicmp(p, SD, wcslen(SD)) == 0) {
        ul = wcslen(SD);
        if (!fl_shared_data(out, cap)) return 0;
    } else return 0;
    return sample_path_join(out, cap, p + ul);
}

// ---- FLP / .fst images ----
#include "../common/flim_flp.h"

static void ev_wstr(const unsigned char *p, size_t n, wchar_t *out, int cap) {
    size_t k = n / 2;
    if (k >= (size_t)cap) k = (size_t)cap - 1;
    memcpy(out, p, k * 2);
    out[k] = 0;
}

typedef struct { wchar_t **paths; int n, cap, failed; } PathList;
#define SAMPLE_REFERENCE_MAX 4096
static void pathlist_add(PathList *L, const wchar_t *w) {
    int i;
    wchar_t *copy;
    if (!w[0] || L->failed) return;
    for (i = 0; i < L->n; i++) if (_wcsicmp(L->paths[i], w) == 0) return;
    if (L->n >= SAMPLE_REFERENCE_MAX) { L->failed = 1; return; }
    if (L->n == L->cap) {
        int cap = L->cap ? L->cap * 2 : 16;
        wchar_t **paths = (wchar_t **)realloc(L->paths, sizeof(wchar_t *) * cap);
        if (!paths) { L->failed = 1; return; }
        L->paths = paths; L->cap = cap;
    }
    copy = _wcsdup(w);
    if (!copy) { L->failed = 1; return; }
    L->paths[L->n++] = copy;
}

// ---- paths inside plugin data ----
static int audio_ext(const wchar_t *w, size_t n) {
    static const wchar_t *const EXT[] = { L".wav", L".mp3", L".ogg", L".flac", L".aif", L".aiff", L".wv", L".rx2", L".rex", L".sf2" };
    size_t i, k;
    for (i = 0; i < sizeof(EXT) / sizeof(EXT[0]); i++) {
        k = wcslen(EXT[i]);
        if (n > k && _wcsnicmp(w + n - k, EXT[i], k) == 0) return 1;
    }
    return 0;
}
// [tag u32][length u64][payload] records exactly covering v[a, b)?
static int tlv_valid(const unsigned char *v, size_t a, size_t b) {
    if (a >= b) return 0;
    while (a < b) {
        uint64_t ln;
        if (b - a < 12) return 0;
        ln = *(const uint64_t *)(v + a + 4);
        if (ln > b - a - 12) return 0;
        a += 12 + (size_t)ln;
    }
    return 1;
}
// Image-Line plugin data: a 4-byte header (FPC) or none, then TLV records. -1 = not that layout.
static int tlv_start(const unsigned char *v, size_t n) {
    if (tlv_valid(v, 4, n)) return 4;
    if (tlv_valid(v, 0, n)) return 0;
    return -1;
}
// A TLV payload that is a sample path (UTF-16, optional trailing NUL) -> out. 0 = not one.
static int tlv_path(const unsigned char *p, size_t n, wchar_t *out, int cap) {
    size_t k = n / 2, i;
    if (n < 8 || (n & 1) || k >= (size_t)cap) return 0;
    memcpy(out, p, k * 2);
    out[k] = 0;
    if (k && !out[k - 1]) k--;
    for (i = 0; i < k; i++) if (out[i] < 32) return 0;
    out[k] = 0;
    return (is_abs_path(out) || out[0] == L'%') && audio_ext(out, k);
}
static void tlv_collect(const unsigned char *v, size_t a, size_t b, int depth, PathList *L) {
    wchar_t w[SAMPLE_PATH_MAX];
    while (a < b) {
        size_t s = a + 12, e = s + (size_t)*(const uint64_t *)(v + a + 4);
        if (tlv_path(v + s, e - s, w, SAMPLE_PATH_MAX)) pathlist_add(L, w);
        else if (depth < 8 && tlv_valid(v, s, e)) tlv_collect(v, s, e, depth + 1, L);
        a = e;
    }
}
// Plain absolute paths anywhere in the data: "X:\..." / "\\..." as UTF-16LE or ANSI,
// ending in an audio extension. *wide tells which encoding was found (for the rewrite).
static size_t raw_path_at(const unsigned char *v, size_t i, size_t n, int wide, wchar_t *out, int cap) {
    size_t k = 0, step = wide ? 2 : 1;
    while (i + k * step + step <= n && k + 1 < (size_t)cap) {
        unsigned c = wide ? *(const uint16_t *)(v + i + k * step) : v[i + k * step];
        if (c < 32 || c == '"' || c == '*' || c == '?' || c == '<' || c == '>' || c == '|') break;
        out[k++] = (wchar_t)c;
    }
    out[k] = 0;
    if (!wide && k) {                                       // ANSI: decode with the system code page
        char a[SAMPLE_PATH_MAX];
        size_t j;
        for (j = 0; j < k; j++) a[j] = (char)v[i + j];
        a[k] = 0;
        if (!MultiByteToWideChar(CP_ACP, 0, a, -1, out, cap)) return 0;
    }
    while (k > 4 && !audio_ext(out, wcslen(out))) {         // the string may run on into other data
        out[--k] = 0;
        if (!wide) { out[0] = 0; return 0; }
    }
    return is_abs_path(out) && audio_ext(out, wcslen(out)) ? k : 0;
}
static int raw_starts(const unsigned char *v, size_t i, size_t n, int wide) {
    size_t st = wide ? 2 : 1;
    unsigned c0, c1, c2;
    if (i + 3 * st > n) return 0;
    c0 = wide ? *(const uint16_t *)(v + i) : v[i];
    c1 = wide ? *(const uint16_t *)(v + i + st) : v[i + st];
    c2 = wide ? *(const uint16_t *)(v + i + 2 * st) : v[i + 2 * st];
    if (wide && (v[i + 1] || v[i + 3])) return 0;
    return ((c0 | 0x20) >= 'a' && (c0 | 0x20) <= 'z' && c1 == ':' && (c2 == '\\' || c2 == '/')) || (c0 == '\\' && c1 == '\\');
}
static void raw_collect(const unsigned char *v, size_t n, PathList *L) {
    wchar_t w[SAMPLE_PATH_MAX];
    size_t i, k;
    int wide;
    for (wide = 1; wide >= 0; wide--)
        for (i = 0; i + 8 < n; i++)
            if (raw_starts(v, i, n, wide) && (k = raw_path_at(v, i, n, wide, w, SAMPLE_PATH_MAX)) != 0) {
                pathlist_add(L, w);
                i += k * (wide ? 2 : 1) - 1;
            }
}

static int collect_cb(void *ctx, uint32_t id, const unsigned char *p, size_t n, size_t at, size_t end) {
    PathList *L = (PathList *)ctx;
    wchar_t w[SAMPLE_PATH_MAX];
    (void)at; (void)end;
    if (id == EV_PLUGIN_DATA && n >= 12) {
        int st = tlv_start(p, n);
        if (st >= 0) tlv_collect(p, (size_t)st, n, 0, L);
        raw_collect(p, n, L);
        return 1;
    }
    if (id != EV_SAMPLE_PATH || n < 4) return 1;
    ev_wstr(p, n, w, SAMPLE_PATH_MAX);
    pathlist_add(L, w);
    return 1;
}
static void pathlist_free(PathList *L) {
    int i;
    for (i = 0; i < L->n; i++) free(L->paths[i]);
    free(L->paths);
    memset(L, 0, sizeof(*L));
}

#define SAMPLE_REWRITE_MAX (128u * 1024u * 1024u)
typedef struct { unsigned char *o; size_t n, cap; int changed, failed; const unsigned char *d; } RewriteCtx;
static void rw_put(RewriteCtx *c, const void *p, size_t n) {
    size_t need, cap;
    unsigned char *next;
    if (c->failed || !n) return;
    if (!p || c->n > SAMPLE_REWRITE_MAX || n > SAMPLE_REWRITE_MAX - c->n) { c->failed = 1; return; }
    need = c->n + n;
    if (need > c->cap) {
        cap = need > (SAMPLE_REWRITE_MAX - 1024) / 2 ? SAMPLE_REWRITE_MAX : need * 2 + 1024;
        next = (unsigned char *)realloc(c->o, cap);
        if (!next) { c->failed = 1; return; }
        c->o = next; c->cap = cap;
    }
    memcpy(c->o + c->n, p, n);
    c->n += n;
}
static void rw_event(RewriteCtx *c, int id, const unsigned char *p, size_t len) {
    unsigned char b = (unsigned char)id;
    size_t v = len;
    rw_put(c, &b, 1);
    do { b = (unsigned char)(v & 0x7f); v >>= 7; if (v) b |= 0x80; rw_put(c, &b, 1); } while (v);
    rw_put(c, p, len);
}
static const wchar_t *map_find(const wchar_t *from) {   // caller holds g_sampleLock
    int i;
    for (i = 0; i < g_npmap; i++) if (_wcsicmp(g_pmap[i].from, from) == 0) return g_pmap[i].to;
    return NULL;
}
// TLV records of v[a, b) into c, mapped path leaves replaced (lengths follow). Caller holds g_sampleLock.
static void tlv_rewrite(const unsigned char *v, size_t a, size_t b, int depth, RewriteCtx *c) {
    wchar_t w[SAMPLE_PATH_MAX];
    while (a < b && !c->failed) {
        size_t s = a + 12, e = s + (size_t)*(const uint64_t *)(v + a + 4);
        const wchar_t *to = tlv_path(v + s, e - s, w, SAMPLE_PATH_MAX) ? map_find(w) : NULL;
        RewriteCtx sub;
        uint64_t ln;
        memset(&sub, 0, sizeof(sub));
        if (to) {
            int nul = e - s >= 2 && !v[e - 1] && !v[e - 2];
            rw_put(&sub, to, wcslen(to) * 2);
            if (nul) rw_put(&sub, L"", 2);
            c->changed = 1;
        } else if (depth < 8 && tlv_valid(v, s, e)) {
            sub.d = v;
            tlv_rewrite(v, s, e, depth + 1, &sub);
            if (sub.changed) c->changed = 1;
        } else rw_put(&sub, v + s, e - s);
        if (sub.failed) { free(sub.o); c->failed = 1; return; }
        ln = sub.n;
        rw_put(c, v + a, 4);
        rw_put(c, &ln, 8);
        if (sub.n) rw_put(c, sub.o, sub.n);
        free(sub.o);
        a = e;
    }
}
static int samples_dir(wchar_t *out, int cap);
// Hard links need only an identity check; copies must match byte for byte.
static int same_sample_file(const wchar_t *a, const wchar_t *b) {
    HANDLE fa = INVALID_HANDLE_VALUE, fb = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION ia, ib;
    unsigned char *buf = NULL;
    DWORD na, nb;
    int equal = 0;
    fa = CreateFileW(a, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    fb = CreateFileW(b, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (fa == INVALID_HANDLE_VALUE || fb == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandle(fa, &ia) || !GetFileInformationByHandle(fb, &ib) ||
        ia.nFileSizeHigh != ib.nFileSizeHigh || ia.nFileSizeLow != ib.nFileSizeLow ||
        (ia.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (ib.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) goto done;
    if ((ia.nFileIndexHigh || ia.nFileIndexLow) && ia.dwVolumeSerialNumber == ib.dwVolumeSerialNumber &&
        ia.nFileIndexHigh == ib.nFileIndexHigh && ia.nFileIndexLow == ib.nFileIndexLow) { equal = 1; goto done; }
    buf = (unsigned char *)malloc(128 * 1024);
    if (!buf) goto done;
    for (;;) {
        if (!ReadFile(fa, buf, 64 * 1024, &na, NULL) || !ReadFile(fb, buf + 64 * 1024, 64 * 1024, &nb, NULL) ||
            na != nb || memcmp(buf, buf + 64 * 1024, na)) break;
        if (!na) { equal = 1; break; }
    }
done:
    free(buf);
    if (fa != INVALID_HANDLE_VALUE) CloseHandle(fa);
    if (fb != INVALID_HANDLE_VALUE) CloseHandle(fb);
    return equal;
}
// A local name for `to` that is exactly `len` characters long (plain paths in plugin data
// keep their length): <samples>\<folder>\<name>, a hard link (or copy) of the file.
static int alias_path(const wchar_t *to, size_t len, wchar_t *out, int cap) {
    wchar_t dir[MAX_PATH], name[MAX_PATH], folder[MAX_PATH], h[17];
    const wchar_t *b = to + wcslen(to), *ext;
    size_t fixed, k, i;
    uint64_t fh = 1469598103934665603ull;
    while (b > to && b[-1] != L'\\' && b[-1] != L'/') b--;
    ext = wcsrchr(b, L'.');
    if (cap <= 0 || !samples_dir(dir, MAX_PATH) || wcslen(b) >= MAX_PATH) return 0;
    wcscpy_s(name, MAX_PATH, b);
    fixed = wcslen(dir) + 2;                                // two backslashes
    if (fixed + wcslen(name) + 1 > len) {                   // too long: a short name keeps the extension
        swprintf_s(name, MAX_PATH, L"s%s", ext ? ext : L"");
        if (fixed + wcslen(name) + 1 > len) return 0;
    }
    k = len - fixed - wcslen(name);
    if (k >= MAX_PATH || len >= (size_t)cap || len >= MAX_PATH) return 0;
    for (i = 0; to[i]; i++) { fh ^= to[i]; fh *= 1099511628211ull; }
    swprintf_s(h, 17, L"%016llx", (unsigned long long)fh);
    for (i = 0; i < k; i++) folder[i] = i < 16 ? h[i] : L'_';
    folder[k] = 0;
    swprintf_s(out, cap, L"%s\\%s\\%s", dir, folder, name);
    if (wcslen(out) != len) return 0;
    if (file_exists_w(out)) {                               // made earlier: must be this file (short names can collide)
        if (!same_sample_file(out, to)) return 0;
    } else {
        wchar_t d2[MAX_PATH * 2];
        swprintf_s(d2, MAX_PATH * 2, L"%s\\%s", dir, folder);
        SHCreateDirectoryExW(NULL, d2, NULL);
        if (!CreateHardLinkW(out, to, NULL) && !CopyFileW(to, out, TRUE)) return 0;
    }
    return 1;
}
// Same-length replacement of plain paths in plugin data (in place). Caller holds g_sampleLock.
static int raw_rewrite(unsigned char *v, size_t n) {
    wchar_t w[SAMPLE_PATH_MAX], al[SAMPLE_PATH_MAX];
    size_t i, k, j;
    int wide, changed = 0;
    for (wide = 1; wide >= 0; wide--)
        for (i = 0; i + 8 < n; i++) {
            const wchar_t *to;
            if (!raw_starts(v, i, n, wide) || (k = raw_path_at(v, i, n, wide, w, SAMPLE_PATH_MAX)) == 0) continue;
            to = map_find(w);
            if (to && wcslen(w) == k && alias_path(to, k, al, SAMPLE_PATH_MAX)) {
                int ascii = 1;
                for (j = 0; j < k; j++) ascii &= al[j] < 128;
                if (wide) memcpy(v + i, al, k * 2);
                else if (ascii) for (j = 0; j < k; j++) v[i + j] = (unsigned char)al[j];
                else return -1;
                changed = 1;
                logmsg("SAMPLES plugin data: %S -> %S", w, al);
            } else if (to) return -1;
            i += k * (wide ? 2 : 1) - 1;
        }
    return changed;
}

// Caller holds g_sampleLock.
static int rewrite_cb(void *ctx, uint32_t id, const unsigned char *p, size_t n, size_t at, size_t end) {
    RewriteCtx *c = (RewriteCtx *)ctx;
    wchar_t w[SAMPLE_PATH_MAX];
    int i;
    if (c->failed) return 0;
    if (id == EV_PLUGIN_DATA && n >= 12) {
        RewriteCtx t;
        int st = tlv_start(p, n), ch = 0, raw;
        memset(&t, 0, sizeof(t));
        if (st >= 0) {
            t.d = p;
            rw_put(&t, p, (size_t)st);
            tlv_rewrite(p, (size_t)st, n, 0, &t);
            ch = t.changed;
        } else rw_put(&t, p, n);
        if (t.failed) { free(t.o); c->failed = 1; return 0; }
        raw = raw_rewrite(t.o, t.n);
        if (raw < 0) { free(t.o); c->failed = 2; return 0; }
        if (raw) ch = 1;
        if (ch) { rw_event(c, id, t.o, t.n); c->changed = 1; }
        else rw_put(c, c->d + at, end - at);
        free(t.o);
        return !c->failed;
    }
    if (id == EV_SAMPLE_PATH && n >= 4) {
        ev_wstr(p, n, w, SAMPLE_PATH_MAX);
        for (i = 0; i < g_npmap; i++) {
            if (_wcsicmp(g_pmap[i].from, w) != 0) continue;
            rw_event(c, id, (const unsigned char *)g_pmap[i].to, (wcslen(g_pmap[i].to) + 1) * 2);   // UTF-16LE + NUL
            c->changed = 1;
            return 1;
        }
    }
    rw_put(c, c->d + at, end - at);
    return !c->failed;
}

// Receiver: point the sample paths in an inbound .flp / .fst image at the local files.
static void samples_rewrite(unsigned char **d, size_t *n) {
    RewriteCtx c;
    size_t start, end;
    int ok;
    if (!d || !n || !*d || !flp_data_bounds(*d, *n, &start, &end)) return;
    memset(&c, 0, sizeof(c));
    c.d = *d;
    EnterCriticalSection(&g_sampleLock);
    if (!g_npmap) { LeaveCriticalSection(&g_sampleLock); return; }
    rw_put(&c, *d, start);
    ok = flp_walk(*d, *n, rewrite_cb, &c);
    LeaveCriticalSection(&g_sampleLock);
    if (c.failed) goto failed;
    if (!ok || !c.changed) { free(c.o); return; }
    if (c.n - start > UINT32_MAX) { free(c.o); return; }
    *(uint32_t *)(c.o + start - 4) = (uint32_t)(c.n - start);        // FLdt chunk length
    rw_put(&c, *d + end, *n - end);
    if (c.failed) goto failed;
    logmsg("SAMPLES paths rewritten to local files (%zu -> %zu bytes)", *n, c.n);
    free(*d);
    *d = c.o;
    *n = c.n;
    return;
failed:
    free(c.o);
    sharing_fail("Sample paths: session stopped", c.failed == 2 ?
        "A plugin's sample path could not be safely mapped to the correct local file. The original data was kept." :
        "The shared file could not fit in memory while updating sample paths. The original data was kept.");
}

// FL's older loader can crash on newer projects. A negotiated session may load a verified
// older host's snapshot forward; the version event itself is never rewritten.
#define EV_FL_VERSION 199

// a.b.c.d compared numerically: <0, 0, >0
static int ver_cmp(const char *x, const char *y) { return flim_version_cmp(x, y); }

typedef struct { char version[32]; int seen, invalid; } FlpVersion;

static int valid_fl_version(const char *v) { unsigned parts[4]; return flim_version_parse(v, parts); }

static int version_cb(void *ctx, uint32_t id, const unsigned char *p, size_t n, size_t at, size_t end) {
    FlpVersion *state = (FlpVersion *)ctx;
    char version[32];
    (void)at; (void)end;
    if (id != EV_FL_VERSION) return 1;
    if (n && !p[n - 1]) n--;
    if (!n || n >= sizeof(version) || memchr(p, 0, n)) { state->invalid = 1; return 1; }
    memcpy(version, p, n);
    version[n] = 0;
    if (!valid_fl_version(version)) { state->invalid = 1; return 1; }
    if (state->seen && ver_cmp(state->version, version)) state->invalid = 1;
    else strcpy_s(state->version, sizeof(state->version), version);
    state->seen = 1;
    return 1;                                   // conflicting later versions must also be checked
}

static FlpBuildCheck flp_check_build(const unsigned char *d, size_t n, char *theirs, char *mine) {
    FlpVersion state = {0};
    theirs[0] = mine[0] = 0;
    if (!WideCharToMultiByte(CP_UTF8, 0, g_fl.build, -1, mine, 32, NULL, NULL) || !valid_fl_version(mine))
        return FLP_BUILD_INVALID;
    if (!d || !flp_walk(d, n, version_cb, &state) || !state.seen || state.invalid) return FLP_BUILD_INVALID;
    strcpy_s(theirs, 32, state.version);
    if (g_compatReady && strcmp(theirs, g_hostFlBuild)) return FLP_BUILD_MISMATCH;
    if (!ver_cmp(theirs, mine)) return FLP_BUILD_MATCH;
    if (g_compatReady && flim_version_family(theirs) && flim_version_family(mine) &&
        !strcmp(theirs, g_hostFlBuild) && ver_cmp(theirs, mine) < 0) return FLP_BUILD_FORWARD;
    return FLP_BUILD_MISMATCH;
}

// ---- blob store (HTTP) ----
static __declspec(thread) int g_sampleHttp;
static __declspec(thread) int g_sampleRetry;
static __declspec(thread) int g_sampleLocalError;
static __declspec(thread) int g_sampleVerificationError;
static __declspec(thread) int g_peerHttp;
static volatile LONG g_peerReady;

static int peer_endpoint(NetUrl *url, char key[65]) {
    char address[128], *end; unsigned long port;
    DWORD n = GetEnvironmentVariableA("FLIM_PEER_URL", address, sizeof(address));
    if (!n || n >= sizeof(address) || strncmp(address, "http://127.0.0.1:", 17) || n < 18 || n > 22) return 0;
    port = strtoul(address + 17, &end, 10);
    if (*end || !port || port > 65535 || address[17] < '0' || address[17] > '9') return 0;
    n = GetEnvironmentVariableA("FLIM_PEER_TOKEN", key, 65);
    return n == 64 && is_hex64(key) && parse_host(address, url);
}
static volatile LONG64 g_sampleBlockedUntil;

static int sample_retryable(DWORD status, int download) {
    return !status || status == 408 || status == 425 || status == 429 || status == 500 ||
        status == 502 || status == 503 || status == 504 || status == 507 || (download && status == 404);
}

static DWORD sample_retry_delay(unsigned attempt, ULONGLONG now, ULONGLONG blocked) {
    DWORD delay = attempt < 5 ? (1000u << attempt) : 30000u;
    if (blocked > now && blocked - now > delay) delay = (DWORD)(blocked - now > 60000 ? 60000 : blocked - now);
    return delay;
}

static int sample_retry_wait(unsigned attempt) {
    DWORD remaining = sample_retry_delay(attempt, GetTickCount64(), (ULONGLONG)InterlockedCompareExchange64(&g_sampleBlockedUntil, 0, 0));
    logmsg("SAMPLES pending edit: automatic retry in %lu ms (round %u)", remaining, attempt + 1);
    while (remaining && session_current() && !g_compatFault) {
        DWORD slice = remaining > 100 ? 100 : remaining;
        Sleep(slice); remaining -= slice;
    }
    return session_current() && !g_compatFault;
}

static void sample_failed(DWORD status, int verification) {
    int blocked = status == 429 || status == 507;
    if (verification) g_sampleRetry = 1;
    ff_finish(blocked ? "blocked" : g_sampleRetry ? "waiting" : "failed",
        blocked ? "allowance" : verification ? "verification" : g_sampleRetry ? "retrying" : "network");
}
static void sample_local_failed(void) {
    g_sampleRetry = 1;
    ff_finish("waiting", "local_cache");
    logmsg("SAMPLES local destination unavailable: edit retained; room stays connected");
}
// One request to the server's blob store. Returns the HTTP status (0 = failed).
//   up/upSize: PUT body streamed from this file; body/bodyN: small in-memory body;
//   down: response body written to this file (downHex = its sha256); resp: small text response.
static DWORD blob_http(const wchar_t *verb, const char *what, const wchar_t *up, uint64_t upSize,
                       const char *body, DWORD bodyN, const wchar_t *down, char *downHex, char *resp, int respCap, uint64_t expectedBytes) {
    NetUrl u;
    char key[65];
    wchar_t path[700], wwhat[200], hdr[128];
    HINTERNET ses = NULL, con = NULL, req = NULL;
    DWORD status = 0, sl = sizeof(status), err = 0;
    unsigned char *buf = NULL;
    HANDLE f = INVALID_HANDLE_VALUE;
    size_t pl;
    if (downHex) downHex[0] = 0;
    if (resp && respCap > 0) resp[0] = 0;
    if (g_peerHttp) { if (!session_current() || !peer_endpoint(&u, key)) return 0; }
    else {
        EnterCriticalSection(&g_sampleLock);
        if (!session_current() || !g_blobOn) { LeaveCriticalSection(&g_sampleLock); return 0; }
        u = g_blobUrl; strcpy_s(key, sizeof(key), g_blobKey);
        LeaveCriticalSection(&g_sampleLock);
    }
    wcscpy_s(path, 700, u.path);
    pl = wcslen(path);
    while (pl && path[pl - 1] == L'/') path[--pl] = 0;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, what, -1, wwhat, 200) || pl + wcslen(wwhat) >= 700) goto out;
    wcscat_s(path, 700, wwhat);
    swprintf_s(hdr, 128, L"x-flim-key: %S\r\n", key);
    ses = WinHttpOpen(L"flim/1.0", g_peerHttp ? WINHTTP_ACCESS_TYPE_NO_PROXY : WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) ses = WinHttpOpen(L"flim/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) goto out;
    WinHttpSetTimeouts(ses, 15000, 15000, !strcmp(what, "/blobs/missing") ? 10000 : 120000,
                       !strcmp(what, "/blobs/missing") ? 10000 : 120000);
    if (g_peerHttp) WinHttpSetTimeouts(ses, 500, 500, 2000, down ? 12000 : 2000);
    con = WinHttpConnect(ses, u.host, u.port, 0);
    if (!con) goto out;
    req = WinHttpOpenRequest(con, verb, path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, u.secure ? WINHTTP_FLAG_SECURE : 0);
    if (!req) goto out;
    { DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
      if (!WinHttpSetOption(req, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy))) goto out; }
    buf = (unsigned char *)malloc(BLOB_CHUNK);
    if (!buf) { err = ERROR_NOT_ENOUGH_MEMORY; goto out; }
    if (up) {
        uint64_t left = upSize;
        LARGE_INTEGER actual;
        f = CreateFileW(up, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (f == INVALID_HANDLE_VALUE) goto out;
        if (!GetFileSizeEx(f, &actual) || actual.QuadPart < 0 || (uint64_t)actual.QuadPart != upSize || upSize > MAXDWORD) {err = ERROR_FILE_INVALID; goto out;}
        if (!WinHttpSendRequest(req, hdr, (DWORD)-1L, WINHTTP_NO_REQUEST_DATA, 0, (DWORD)upSize, 0)) goto out;
        while (left) {
            DWORD want = left > BLOB_CHUNK ? BLOB_CHUNK : (DWORD)left, got = 0, sent = 0;
            if (!session_current()) { err = ERROR_OPERATION_ABORTED; goto out; }
            if (!ReadFile(f, buf, want, &got, NULL) || !got) goto out;
            while (sent < got) {
                DWORD wr = 0;
                if (!session_current()) { err = ERROR_OPERATION_ABORTED; goto out; }
                if (!WinHttpWriteData(req, buf + sent, got - sent, &wr) || !wr || wr > got - sent) goto out;
                sent += wr;
                g_xferDone += wr;
                ff_progress(wr);
                xfer_show(0);
            }
            left -= got;
        }
        CloseHandle(f);
        f = INVALID_HANDLE_VALUE;
    } else if (!WinHttpSendRequest(req, hdr, (DWORD)-1L, (LPVOID)body, bodyN, bodyN, 0)) goto out;
    if (!WinHttpReceiveResponse(req, NULL)) goto out;
    if (!WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                        &status, &sl, WINHTTP_NO_HEADER_INDEX)) {status = 0; goto out;}
    if (status == 429 || status == 507) {
        char reason[1024];
        DWORD used = 0, got = 0;
        while (used < sizeof(reason) - 1 && WinHttpReadData(req, reason + used, (DWORD)sizeof(reason) - 1 - used, &got) && got)
            used += got;
        reason[used] = 0;
        if (g_sampleHttp) {
            InterlockedExchange64(&g_sampleBlockedUntil, (LONG64)(GetTickCount64() + 60000));
            logmsg("SAMPLES file allowance reached (HTTP %lu): file transfers paused; room stays connected", status);
        } else if (!g_peerHttp) blob_limit_error(status, reason);
        goto out;
    }
    if (status == 200 && down) {
        Sha s;
        uint64_t received = 0, limit = expectedBytes ? expectedBytes : g_cloudTransport ? FLIM_CLOUD_FILE_MAX : SAMPLE_MAX_BYTES;
        f = CreateFileW(down, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (f == INVALID_HANDLE_VALUE) { g_sampleLocalError = 1; err = GetLastError(); status = 0; goto out; }
        if (!sha_begin(&s)) { err = GetLastError(); status = 0; goto out; }
        for (;;) {
            DWORD got = 0, wr = 0;
            if (!session_current()) { err = ERROR_OPERATION_ABORTED; status = 0; break; }
            if (!WinHttpReadData(req, buf, BLOB_CHUNK, &got)) { err = GetLastError(); status = 0; break; }
            if (!got) break;
            if (!session_current()) { err = ERROR_OPERATION_ABORTED; status = 0; break; }
            if (got > limit - received) { g_sampleVerificationError = 1; err = ERROR_FILE_TOO_LARGE; status = 0; break; }
            received += got;
            if (!sha_add(&s, buf, got)) { err = ERROR_INVALID_DATA; status = 0; break; }
            if (!WriteFile(f, buf, got, &wr, NULL) || wr != got) { g_sampleLocalError = 1; err = GetLastError(); status = 0; break; }
            g_xferDone += got;
            ff_progress(got);
            xfer_show(0);
        }
        if (status == 200 && expectedBytes && received != expectedBytes) { g_sampleVerificationError = 1; err = ERROR_INVALID_DATA; status = 0; }
        if (!sha_end(&s, downHex)) { err = ERROR_INVALID_DATA; status = 0; }
        if (status == 200 && !FlushFileBuffers(f)) { g_sampleLocalError = 1; err = GetLastError(); status = 0; }
    } else if (resp && respCap > 0) {
        int o = 0;
        for (;;) {
            DWORD got = 0;
            if (o >= respCap - 1) {
                char extra;
                if (!WinHttpReadData(req, &extra, 1, &got) || got) status = 0;
                break;
            }
            if (!WinHttpReadData(req, resp + o, (DWORD)(respCap - 1 - o), &got)) { status = 0; break; }
            if (!got) break;
            o += (int)got;
        }
        resp[o] = 0;
    }
out:
    if (status != 200 && downHex) downHex[0] = 0;
    if (!status) logmsg("SAMPLES %S %s failed (%lu)", verb, what, err ? err : GetLastError());
    if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    free(buf);
    if (req) WinHttpCloseHandle(req);
    if (con) WinHttpCloseHandle(con);
    if (ses) WinHttpCloseHandle(ses);
    SecureZeroMemory(key, sizeof(key)); SecureZeroMemory(hdr, sizeof(hdr));
    return status;
}

static DWORD sample_http(const wchar_t *verb, const char *what, const wchar_t *up, uint64_t upSize,
                         const char *body, DWORD bodyN, const wchar_t *down, char *downHex, char *resp, int respCap, uint64_t expectedBytes) {
    DWORD status = 0; int attempt;
    uint64_t startDone = g_xferDone;
    uint64_t startFileDone = ff_active ? ff_current.done : 0;
    g_sampleLocalError = g_sampleVerificationError = 0;
    if (g_peerReady && down && downHex && expectedBytes && !wcscmp(verb, L"GET") && strlen(what) == 70 && !strncmp(what, "/blob/", 6) && is_hex64(what + 6)) {
        NetUrl peer; char peerKey[65], request[160];
        if (peer_endpoint(&peer, peerKey)) {
            uint64_t fileDone = ff_active ? ff_current.done : 0;
            SecureZeroMemory(peerKey, sizeof(peerKey));
            sprintf_s(request, sizeof(request), "%s?bytes=%llu&generation=%ld", what, (unsigned long long)expectedBytes, g_netGen);
            g_peerHttp = 1;
            status = blob_http(verb, request, NULL, 0, NULL, 0, down, downHex, NULL, 0, expectedBytes);
            g_peerHttp = 0;
            if (status == 200 && !strcmp(downHex, what + 6)) { logmsg("P2P sample received and verified (%llu bytes)", (unsigned long long)expectedBytes); return 200; }
            if (g_sampleLocalError || !session_current()) return 0;
            g_xferDone = startDone; g_sampleVerificationError = 0; downHex[0] = 0;
            if (ff_active) {ff_current.done = fileDone; ff_save();}
        }
        SecureZeroMemory(peerKey, sizeof(peerKey));
    }
    if (GetTickCount64() < (ULONGLONG)InterlockedCompareExchange64(&g_sampleBlockedUntil, 0, 0)) { g_sampleRetry = 1; return 507; }
    for (attempt = 0; attempt < 2 && session_current() && !g_compatFault; attempt++) {
        if (attempt) {
            g_xferDone = startDone;
            if (ff_active) { ff_current.done = startFileDone; strcpy_s(ff_current.reason, sizeof(ff_current.reason), "retrying"); ff_save(); }
            Sleep(150);
        }
        g_sampleHttp = 1;
        status = blob_http(verb, what, up, upSize, body, bodyN, down, downHex, resp, respCap, expectedBytes);
        g_sampleHttp = 0;
        if (g_sampleLocalError || g_sampleVerificationError) break;
        if (status && status != 502 && status != 503 && status != 504) break;
    }
    if (sample_retryable(status, down != NULL) || (up && status == 409)) g_sampleRetry = 1;
    return status;
}

static void peer_welcome(const char *message) {
    FlJson root = {message, strlen(message)}, value;
    NetUrl peer; char key[65], token[65], body[160];
    InterlockedExchange(&g_peerReady, 0);
    if (!g_cloudTransport || !peer_endpoint(&peer, key) || !fj_get(root, "file_peer", &value) || !fj_text(value, token, sizeof(token)) || strlen(token) != 64 || !is_hex64(token)) goto done;
    sprintf_s(body, sizeof(body), "{\"token\":\"%s\",\"generation\":%ld}", token, g_netGen);
    g_peerHttp = 1;
    if (blob_http(L"POST", "/connect", NULL, 0, body, (DWORD)strlen(body), NULL, NULL, NULL, 0, 0) == 200) InterlockedExchange(&g_peerReady, 1);
    g_peerHttp = 0;
done:
    SecureZeroMemory(key, sizeof(key)); SecureZeroMemory(token, sizeof(token)); SecureZeroMemory(body, sizeof(body));
}

static void peer_offer(const wchar_t *path, const char *hash, uint64_t bytes) {
    NetUrl peer; char key[65], *body = NULL; size_t cap, at; int i, cached = 0; FILETIME mt = {0}; LONG generation = g_netGen; DWORD status;
    if (!g_peerReady || !g_cloudTransport || generation <= 0 || !session_current() || !path || !hash || !is_hex64(hash) || !bytes || bytes > FLIM_CLOUD_FILE_MAX || wcslen(path) >= SAMPLE_PATH_MAX || !peer_endpoint(&peer, key)) goto done;
    EnterCriticalSection(&g_sampleLock);
    for (i = 0; i < g_nhash; i++) if (!_wcsicmp(g_hashes[i].path, path) && g_hashes[i].size == bytes && !strcmp(g_hashes[i].hex, hash)) {
        if (g_hashes[i].peerGen == generation) {LeaveCriticalSection(&g_sampleLock); goto done;}
        cached = 1; mt = g_hashes[i].mt; break;
    }
    LeaveCriticalSection(&g_sampleLock);
    cap = ((wcslen(path) * 2 + 2) / 3) * 4 + 180;
    body = (char *)malloc(cap); if (!body) goto done;
    at = sprintf_s(body, cap, "{\"generation\":%ld,\"h\":\"%s\",\"s\":%llu,\"p\":\"", generation, hash, (unsigned long long)bytes);
    b64enc((const unsigned char *)path, (int)(wcslen(path) * 2), body + at); strcat_s(body, cap, "\"}");
    g_peerHttp = 1;
    status = blob_http(L"POST", "/offer", NULL, 0, body, (DWORD)strlen(body), NULL, NULL, NULL, 0, 0);
    if (!status) InterlockedExchange(&g_peerReady, 0);
    g_peerHttp = 0;
    if (status == 200 && cached && generation == g_netGen && session_current()) {
        EnterCriticalSection(&g_sampleLock);
        for (i = 0; i < g_nhash; i++) if (!_wcsicmp(g_hashes[i].path, path) && g_hashes[i].size == bytes && !CompareFileTime(&g_hashes[i].mt, &mt) && !strcmp(g_hashes[i].hex, hash)) {g_hashes[i].peerGen = generation; break;}
        LeaveCriticalSection(&g_sampleLock);
    }
done:
    SecureZeroMemory(key, sizeof(key)); free(body);
}

// ---- sender ----
typedef struct { const wchar_t *p; wchar_t *full; char hex[65]; uint64_t size; int upload, skip; } SEnt;

static int sample_sendable(uint64_t bytes) {
    return bytes > 0 && bytes <= (g_cloudTransport ? FLIM_CLOUD_FILE_MAX : SAMPLE_MAX_BYTES);
}

static int samples_missing(SEnt *entries, int count) {
    enum { BATCH = 512, BODY_CAP = BATCH * 65 + 1, RESPONSE_CAP = BATCH * 65 + 16 };
    char *body = (char *)malloc(BODY_CAP), *response = (char *)malloc(RESPONSE_CAP);
    int start, ok = 0;
    if (!body || !response) goto done;
    for (start = 0; start < count; start += BATCH) {
        int i, end = count - start > BATCH ? start + BATCH : count, n = 0;
        char *line, *context = NULL;
        DWORD status;
        if (!session_current()) goto done;
        for (i = start; i < end; i++) n += sprintf_s(body + n, BODY_CAP - n, "%s\n", entries[i].hex);
        status = sample_http(L"POST", "/blobs/missing", NULL, 0, body, (DWORD)n, NULL, NULL, response, RESPONSE_CAP, 0);
        if (status != 200) { logmsg("SAMPLES sample lookup failed (HTTP %lu)", status); goto done; }
        for (line = strtok_s(response, "\r\n", &context); line; line = strtok_s(NULL, "\r\n", &context)) {
            if (strlen(line) != 64 || !is_hex64(line)) goto done;
            for (i = start; i < end; i++) if (!strcmp(entries[i].hex, line)) { entries[i].upload = 1; break; }
            if (i == end) goto done;
        }
    }
    ok = 1;
done:
    if (!ok) { int i; for (i = 0; i < count; i++) entries[i].upload = 0; }
    free(body); free(response);
    return ok;
}

static void group_digits(uint64_t v, wchar_t *out, int cap) {
    wchar_t t[32];
    int n, i, o = 0;
    swprintf_s(t, 32, L"%llu", (unsigned long long)v);
    n = (int)wcslen(t);
    for (i = 0; i < n && o < cap - 2; i++) {
        if (i && (n - i) % 3 == 0) out[o++] = L',';
        out[o++] = t[i];
    }
    out[o] = 0;
}

// Outbox thread: list (and upload) the samples an outgoing project / channel state uses.
// Returns the message with "samples":[...] spliced in, or NULL to send it unchanged.
static char *samples_attach(const char *msg, const unsigned char *blob, size_t n) {
    FlJson root = {msg, strlen(msg)}, operation, existing;
    PathList L;
    SEnt *E = NULL;
    int i, j, ne = 0, nup = 0;
    uint64_t upBytes = 0;
    char *out = NULL;
    memset(&L, 0, sizeof(L));
    if (!session_current()) return NULL;
    if (!fj_get(root, "op", &operation) || operation.n < 2 || operation.p[0] != '{' || fj_get(operation, "samples", &existing)) goto invalid;
    if (!flp_walk(blob, n, collect_cb, &L)) goto invalid;
    if (L.failed) goto memory_failed;
    if (!L.n || !g_blobOn) goto done;
    E = (SEnt *)calloc((size_t)L.n, sizeof(SEnt));
    if (!E) goto memory_failed;
    for (i = 0; i < L.n; i++) {
        wchar_t full[SAMPLE_PATH_MAX];
        uint64_t bytes;
        if (!session_current() || g_compatFault) goto done;
        if (!expand_path(L.paths[i], full, SAMPLE_PATH_MAX)) continue;
        if (!file_info(full, &bytes, NULL)) { ff_begin(full, NULL, "upload", 0, "missing"); ff_finish("missing", "source_missing"); continue; }
        if (!sample_sendable(bytes)) { ff_begin(full, NULL, "upload", bytes, "failed"); ff_finish("failed", bytes ? "too_large" : "empty"); continue; }
        ff_begin(full, NULL, "upload", bytes, "checking");
        if (!sample_hash(full, E[ne].hex, &E[ne].size)) { ff_finish("failed", "source_changed"); continue; }
        if (!sample_sendable(E[ne].size)) {ff_finish("failed", E[ne].size ? "too_large" : "empty"); continue;}
        ff_identify(E[ne].hex);
        ff_finish("checking", "");
        E[ne].p = L.paths[i];
        E[ne].full = _wcsdup(full);
        if (!E[ne].full) goto memory_failed;
        ne++;
    }
    if (!ne) goto done;
    for (i = 0; i < ne; i++) peer_offer(E[i].full, E[i].hex, E[i].size);
    if (!samples_missing(E, ne)) {
        if (!session_current() || g_compatFault) goto done;
        logmsg("SAMPLES lookup unavailable: sample-dependent edit pending while recoverable requests retry");
        for (i = 0; i < ne; i++) {
            int blocked = GetTickCount64() < (ULONGLONG)InterlockedCompareExchange64(&g_sampleBlockedUntil, 0, 0);
            E[i].skip = 1; ff_begin(E[i].full, E[i].hex, "upload", E[i].size, blocked ? "blocked" : g_sampleRetry ? "waiting" : "failed");
            sample_failed(blocked ? 507 : 0, 0);
        }
    }
    for (i = 0; i < ne; i++) if (!E[i].skip && !E[i].upload) {
        ff_begin(E[i].full, E[i].hex, "upload", E[i].size, "ready"); ff_finish("ready", "relay_cache");
    }
    for (i = 0; i < ne; i++) {
        if (!E[i].upload) continue;
        if (declined(E[i].hex)) { E[i].upload = 0; E[i].skip = 1; continue; }
        for (j = 0; j < i && !(E[j].upload && strcmp(E[j].hex, E[i].hex) == 0); j++) {}
        if (j < i) { E[i].upload = 0; continue; }        // same content listed twice: one upload
        upBytes += E[i].size;
        nup++;
    }
    if (nup) logmsg("SAMPLES automatic upload: %llu bytes (%d files), relay limits still apply", (unsigned long long)upBytes, nup);
    if (nup) {
        char what[80];
        g_xferWhat = "Uploading"; g_xferDone = 0; g_xferTotal = upBytes;
        xfer_show(1);
        for (i = 0; i < ne; i++) {
            DWORD st;
            if (!E[i].upload) continue;
            sprintf_s(what, sizeof(what), "/blob/%s", E[i].hex);
            ff_begin(E[i].full, E[i].hex, "upload", E[i].size, "uploading");
            st = sample_http(L"PUT", what, E[i].full, E[i].size, NULL, 0, NULL, NULL, NULL, 0, 0);
            if (st == 200 || st == 201) { ff_finish("ready", "uploaded"); logmsg("SAMPLES uploaded %S (%llu bytes)", E[i].full, (unsigned long long)E[i].size); }
            else {
                sample_failed(st, 0);
                logmsg("SAMPLES upload of %S failed (HTTP %lu): left out", E[i].full, st);
                for (j = 0; j < ne; j++) if (strcmp(E[j].hex, E[i].hex) == 0) E[j].skip = 1;
            }
        }
        xfer_end();
    }
    {   // splice "samples":[...] in front of the op's fields
        const char *op = operation.p + 1;
        size_t cap = strlen(msg) + 64, len;
        int k = 0;
        for (i = 0; i < ne; i++) cap += wcslen(E[i].p) * 3 + 120;
        out = (char *)malloc(cap);
        if (!out) goto memory_failed;
        len = (size_t)(op - msg);
        memcpy(out, msg, len);
        len += sprintf_s(out + len, cap - len, "\"samples\":[");
        for (i = 0; i < ne; i++) {
            if (E[i].skip) continue;
            len += sprintf_s(out + len, cap - len, "%s{\"p\":\"", k++ ? "," : "");
            b64enc((const unsigned char *)E[i].p, (int)(wcslen(E[i].p) * 2), out + len);
            len += strlen(out + len);
            len += sprintf_s(out + len, cap - len, "\",\"h\":\"%s\",\"s\":%llu}", E[i].hex, (unsigned long long)E[i].size);
        }
        { const char *tail = op; fj_space(&tail, operation.p + operation.n);
          len += sprintf_s(out + len, cap - len, *tail == '}' ? "]" : "],"); }
        strcpy_s(out + len, cap - len, op);
        logmsg("SAMPLES op lists %d samples (%d uploaded)", k, nup);
    }
    goto done;
invalid:
    sharing_fail("Sample transfer: session stopped", "The shared preset or its sample metadata is malformed. No sample files were transferred.");
    goto done;
memory_failed:
    sharing_fail("Sample transfer: session stopped", "The sample list exceeded its limit or available memory. Reconnect and resync before continuing to share.");
done:
    if (E) { for (i = 0; i < ne; i++) free(E[i].full); free(E); }
    pathlist_free(&L);
    return out;
}

// Keep the original state until its recoverable file dependencies are ready. Repeating a
// whole edit after it was applied could undo newer notes, moves, or channel deletions.
static char *samples_prepare_send(const char *msg, const unsigned char *blob, size_t n) {
    char *prepared = NULL;
    unsigned attempt = 0;
    if (!session_current() || g_compatFault) return NULL;
    do {
        free(prepared); g_sampleRetry = 0;
        prepared = samples_attach(msg, blob, n);
        if (!g_sampleRetry || !session_current() || g_compatFault) break;
        if (!sample_retry_wait(attempt)) break;
        if (attempt < 30) attempt++;
    } while (session_current());
    return prepared;
}

static int out_push(char *msg, unsigned char *blob, size_t n, LONG generation) {   // caller holds g_outLock; takes ownership on either result
    OutItem *it;
    size_t bytes = msg ? strlen(msg) + 1 : 0;
    if (!msg || generation != g_netGen || g_compatFault || g_outCount >= TRANSFER_QUEUE_MAX_COUNT ||
        n > TRANSFER_QUEUE_MAX_BYTES || bytes > TRANSFER_QUEUE_MAX_BYTES - n ||
        bytes + n > TRANSFER_QUEUE_MAX_BYTES - g_outBytes) { free(msg); free(blob); return 0; }
    it = (OutItem *)calloc(1, sizeof(OutItem));
    if (!it) { free(msg); free(blob); return 0; }
    it->gen = generation; it->msg = msg; it->blob = blob; it->blobn = n; it->bytes = bytes + n;
    if (g_outTail) g_outTail->next = it; else g_outHead = it;
    g_outTail = it;
    g_outBytes += it->bytes; g_outCount++;
    return 1;
}

// Every op goes through here: straight out, unless something is queued in the outbox
// (an op waiting for its samples) -- then behind it, to keep the order.
static void ws_send(const char *msg) {
    int failed = 0;
    LONG generation = session_generation();
    if (generation != g_netGen || !compat_outgoing(msg)) return;
    EnterCriticalSection(&g_outLock);
    if (g_outBusy || g_outHead || (g_cloudTransport && strlen(msg) > FLIM_CLOUD_INLINE)) {
        if (out_push(_strdup(msg), NULL, 0, generation)) SetEvent(g_outEvt);
        else failed = 1;
    }
    else ws_send_now(msg, generation);
    LeaveCriticalSection(&g_outLock);
    if (failed && generation == g_netGen) sharing_fail("Upload backlog: session stopped", "Shared edits exceeded the upload backlog or available memory. Reconnect and resync before continuing to share.");
}

// An op whose data (an .flp / .fst image) may reference samples. Takes ownership of msg.
static void ws_send_samples(char *msg, const unsigned char *blob, size_t n) {
    unsigned char *copy;
    int queued;
    LONG generation = session_generation();
    if (generation != g_netGen || !g_ws || !msg || !compat_outgoing(msg)) { free(msg); return; }
    if (n > TRANSFER_QUEUE_MAX_BYTES || (n && !blob)) {
        free(msg); sharing_fail("Upload backlog: session stopped", "The shared project or preset is too large for the transfer backlog."); return;
    }
    copy = (unsigned char *)malloc(n ? n : 1);
    if (!copy) { free(msg); sharing_fail("Upload backlog: session stopped", "There is not enough memory to queue the shared project or preset."); return; }
    if (n) memcpy(copy, blob, n);
    EnterCriticalSection(&g_outLock);
    queued = out_push(msg, copy, n, generation);
    LeaveCriticalSection(&g_outLock);
    if (queued) SetEvent(g_outEvt);
    else if (generation == g_netGen) sharing_fail("Upload backlog: session stopped", "Shared edits exceeded the upload backlog or available memory. Reconnect and resync before continuing to share.");
}

static DWORD WINAPI outThread(LPVOID p) {
    (void)p;
    for (;;) {
        WaitForSingleObject(g_outEvt, INFINITE);
        for (;;) {
            OutItem *it;
            EnterCriticalSection(&g_outLock);
            it = g_outHead;
            if (!it) { g_outBusy = 0; LeaveCriticalSection(&g_outLock); break; }
            g_outHead = it->next;
            g_outBytes -= it->bytes; g_outCount--;
            if (!g_outHead) g_outTail = NULL;
            g_outBusy = 1;
            LeaveCriticalSection(&g_outLock);
            g_workBound = 1; g_workGen = it->gen;
            if (session_current() && it->blob) {
                char *m2 = samples_prepare_send(it->msg, it->blob, it->blobn);
                if (m2) { free(it->msg); it->msg = m2; }
            }
            if (session_current() && !g_compatFault && g_cloudTransport && strlen(it->msg) > FLIM_CLOUD_INLINE) {
                char hx[65], what[80], header[1024]; DWORD status;
                size_t size = strlen(it->msg);
                if (size > FLIM_CLOUD_MAX || !sha_hex(it->msg, size, hx) || !fc_header(it->msg, hx, header, sizeof(header))) {
                    cloud_fail("This edit is too large or cannot be safely sent through the Cloudflare relay.");
                } else {
                    sprintf_s(what, sizeof(what), "/blob/%s", hx);
                    status = blob_http(L"PUT", what, NULL, 0, it->msg, (DWORD)size, NULL, NULL, NULL, 0, 0);
                    if (session_current()) {
                        if ((status == 200 || status == 201) && compat_outgoing(it->msg)) {
                            logmsg("CLOUD uploaded serialized edit (%llu bytes)", (unsigned long long)size);
                            char *reference = _strdup(header);
                            if (reference) { free(it->msg); it->msg = reference; }
                            else cloud_fail("There is not enough memory to send the shared edit reference. Reconnect and resync before continuing to share.");
                        } else cloud_fail("The relay could not store this edit. Its file allowance may be full, or the connection failed. Reconnect and resync before continuing to share.");
                    }
                }
            }
            EnterCriticalSection(&g_outLock);        // direct senders wait: nothing overtakes this one
            ws_send_now(it->msg, it->gen);
            LeaveCriticalSection(&g_outLock);
            free(it->msg); free(it->blob); free(it);
            g_workBound = 0;
        }
    }
}

// ---- receiver ----
static int samples_dir(wchar_t *out, int cap) {
    DWORD k;
    wchar_t documents[MAX_PATH];
    if (cap <= 0) return 0;
    out[0] = 0;
    SetLastError(ERROR_SUCCESS);
    k = GetEnvironmentVariableW(L"FLIM_SAMPLE_DIR", out, cap);
    if (k || GetLastError() != ERROR_ENVVAR_NOT_FOUND) {
        size_t i;
        if (!k || k >= (DWORD)cap || k > 180 || !is_abs_path(out) ||
            (out[0] == L'\\' && out[1] == L'\\' && (out[2] == L'?' || out[2] == L'.'))) { out[0] = 0; return 0; }
        for (i = 0; i < k; i++) if (out[i] < 32 || wcschr(L"<>\"|?*", out[i]) || (out[i] == L':' && i != 1)) { out[0] = 0; return 0; }
        while (k > 3 && (out[k - 1] == L'\\' || out[k - 1] == L'/')) out[--k] = 0;
        return 1;
    }
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_PERSONAL, NULL, SHGFP_TYPE_CURRENT, documents)) || !*documents ||
        !is_abs_path(documents) || wcslen(documents) >= (size_t)cap) return 0;
    wcscpy_s(out, cap, documents);
    if (!sample_path_join(out, cap, L"flim\\samples") || wcslen(out) > 180) {out[0] = 0; return 0;}
    return 1;
}

// Where a downloaded sample is kept: samples\<first 16 hex>\<its file name>.
static int cache_path(const char *hex, const wchar_t *p, wchar_t *out, int cap) {
    wchar_t dir[MAX_PATH], name[MAX_PATH], extension[18] = L"", stem[8];
    const wchar_t *b = p + wcslen(p);
    const wchar_t *ext;
    size_t i, n, room, root, base;
    if (cap <= 0) return 0;
    out[0] = 0;
    if (!hex || strlen(hex) != 64 || !is_hex64(hex) || !samples_dir(dir, MAX_PATH)) return 0;
    while (b > p && b[-1] != L'\\' && b[-1] != L'/') b--;
    ext = wcsrchr(b, L'.');
    if (ext && wcslen(ext) > 1 && wcslen(ext) <= 16) wcscpy_s(extension, 18, ext);
    for (i = 0; extension[i]; i++) if (wcschr(L"\\/:*?\"<>|", extension[i]) || extension[i] < 32) extension[i] = L'_';
    i = wcslen(extension);
    while (i && (extension[i - 1] == L'.' || extension[i - 1] == L' ')) extension[--i] = 0;
    wcsncpy_s(name, MAX_PATH, *b ? b : L"sample.wav", _TRUNCATE);
    for (i = 0; name[i]; i++) if (wcschr(L"\\/:*?\"<>|", name[i]) || name[i] < 32) name[i] = L'_';
    n = wcslen(name);
    while (n && (name[n - 1] == L'.' || name[n - 1] == L' ')) name[--n] = 0;
    if (!n) {wcscpy_s(name, MAX_PATH, L"sample.wav"); n = wcslen(name);}
    base = wcscspn(name, L". ");
    if (base < 8) {
        memcpy(stem, name, base * sizeof(wchar_t)); stem[base] = 0;
        if (!_wcsicmp(stem, L"CON") || !_wcsicmp(stem, L"PRN") || !_wcsicmp(stem, L"AUX") || !_wcsicmp(stem, L"NUL") ||
            (base == 4 && (!_wcsnicmp(stem, L"COM", 3) || !_wcsnicmp(stem, L"LPT", 3)) && stem[3] >= L'1' && stem[3] <= L'9')) {
            if (n + 1 < MAX_PATH) {memmove(name + 1, name, (n + 1) * sizeof(wchar_t)); n++;}
            name[0] = L'_';
        }
    }
    root = wcslen(dir) + 18;
    room = (cap < MAX_PATH ? (size_t)cap : MAX_PATH) - 1;
    if (room <= root + 17) return 0;
    room -= root;
    if (n > room) {
        size_t keep = room - wcslen(extension);
        if (keep && name[keep - 1] >= 0xd800 && name[keep - 1] <= 0xdbff) keep--;
        name[keep] = 0;
        wcscat_s(name, MAX_PATH, extension);
    }
    return swprintf_s(out, cap, L"%s\\%.16S\\%s", dir, hex, name) > 0;
}

static int sample_source_valid(const wchar_t *p, size_t n) {
    size_t i;
    if (!n || n >= SAMPLE_PATH_MAX || wcslen(p) != n) return 0;
    if (!is_abs_path(p) && _wcsnicmp(p, L"%FLStudioUserData%", 18) && _wcsnicmp(p, L"%ILSharedData%", 14)) return 0;
    if (p[0] == L'\\' && p[1] == L'\\' && (p[2] == L'?' || p[2] == L'.' || !p[2])) return 0;
    for (i = 0; i < n; i++) {
        unsigned c = p[i];
        if (c < 32 || c == 127 || wcschr(L"<>\"|?*", c) || (c == L':' && i != 1)) return 0;
        if (c >= 0xd800 && c <= 0xdbff) { if (++i == n || p[i] < 0xdc00 || p[i] > 0xdfff) return 0; }
        else if (c >= 0xdc00 && c <= 0xdfff) return 0;
    }
    return 1;
}

typedef struct { wchar_t *p; char hex[65]; uint64_t size; wchar_t cache[MAX_PATH * 2]; int need; } REnt;

// Inbox thread: make the samples an inbound op lists available here and record the path
// rewrites for its data.
static void samples_resolve(const char *m) {
    FlJson root = {m, strlen(m)}, op, samples;
    const char *q, *end;
    REnt *R = NULL;
    int nr = 0, cap = 0, i, nneed = 0, nfail = 0, downloaded = 0;
    uint64_t total = 0;
    if (!fj_get(root, "op", &op) || !fj_get(op, "samples", &samples)) return;
    if (samples.n < 2 || samples.p[0] != '[') goto invalid;
    q = samples.p + 1; end = samples.p + samples.n;
    fj_space(&q, end);
    while (q < end && *q != ']') {
        FlJson item, path, value;
        const char *start = q;
        char hex[65]; uint64_t bytes;
        size_t bn, encoded, decodedBytes;
        unsigned char *b;
        wchar_t *decoded;
        if (nr >= SAMPLE_REFERENCE_MAX || !fj_value(&q, end, 0)) goto invalid;
        item.p = start; item.n = (size_t)(q - start);
        if (!fj_get(item, "p", &path) || path.n < 6 || path.p[0] != '"' || path.n > 4 * ((SAMPLE_PATH_MAX * 2 + 2) / 3) + 2 ||
            !fj_get(item, "h", &value) || !fj_text(value, hex, sizeof(hex)) || strlen(hex) != 64 || !is_hex64(hex) ||
            !fj_get(item, "s", &value) || !fc_uint(value, &bytes) || !sample_sendable(bytes)) goto invalid;
        { FlJson data;
          if (!shared_b64(path, &data, SAMPLE_PATH_MAX * 2 - 2, &decodedBytes)) goto invalid;
          encoded = data.n; }
        b = b64dec(path.p + 1, encoded, &bn);
        if (!b) goto invalid;
        if (!bn || bn % 2 || bn >= SAMPLE_PATH_MAX * 2) { free(b); goto invalid; }
        decoded = (wchar_t *)calloc(bn / 2 + 1, 2);
        if (!decoded) { free(b); goto invalid; }
        memcpy(decoded, b, bn); free(b);
        if (!sample_source_valid(decoded, bn / 2)) { free(decoded); goto invalid; }
        { int previous;
          for (previous = 0; previous < nr && _wcsicmp(R[previous].p, decoded); previous++) {}
          if (previous < nr) {
              int conflict = strcmp(R[previous].hex, hex) || R[previous].size != bytes;
              free(decoded); if (conflict) goto invalid;
              goto next_sample;
          }
          for (previous = 0; previous < nr; previous++)
              if (!strcmp(R[previous].hex, hex) && R[previous].size != bytes) { free(decoded); goto invalid; }
        }
        if (nr == cap) {
            int next = cap ? cap * 2 : 16;
            REnt *items = (REnt *)realloc(R, sizeof(REnt) * next);
            if (!items) { free(decoded); goto invalid; }
            R = items; cap = next;
        }
        memset(&R[nr], 0, sizeof(REnt)); R[nr].p = decoded;
        strcpy_s(R[nr].hex, sizeof(R[nr].hex), hex); R[nr++].size = bytes;
next_sample:
        fj_space(&q, end);
        if (q < end && *q == ',') { q++; fj_space(&q, end); }
    }
    for (i = 0; i < nr; i++) {
        wchar_t full[SAMPLE_PATH_MAX], found[SAMPLE_PATH_MAX];
        char hx[65];
        uint64_t sz;
        if (!g_noLocal && expand_path(R[i].p, full, SAMPLE_PATH_MAX) && full[1] == L':' && sample_hash(full, hx, &sz) && sz == R[i].size && strcmp(hx, R[i].hex) == 0) {
            map_set(R[i].p, NULL);                      // the same file is right where the peer has it
            ff_begin(R[i].p, R[i].hex, "download", R[i].size, "ready"); ff_finish("ready", "local_cache");
            peer_offer(full, R[i].hex, R[i].size);
            continue;
        }
        if (!g_noLocal && find_by_hash(R[i].hex, found, SAMPLE_PATH_MAX) && file_info(found, &sz, NULL) && sz == R[i].size) {
            map_set(R[i].p, found); ff_begin(R[i].p, R[i].hex, "download", R[i].size, "ready"); ff_finish("ready", "local_cache"); peer_offer(found, R[i].hex, R[i].size); continue;
        }
        if (!cache_path(R[i].hex, R[i].p, R[i].cache, MAX_PATH * 2)) {
            map_set(R[i].p, NULL); ff_begin(R[i].p, R[i].hex, "download", R[i].size, "waiting"); sample_local_failed(); goto done;
        }
        if (sample_hash(R[i].cache, hx, &sz) && sz == R[i].size && strcmp(hx, R[i].hex) == 0) {
            map_set(R[i].p, R[i].cache); ff_begin(R[i].p, R[i].hex, "download", R[i].size, "ready"); ff_finish("ready", "local_cache"); peer_offer(R[i].cache, R[i].hex, R[i].size); continue;
        }
        /* A replacement must never reuse the previous contents at this peer path. */
        map_set(R[i].p, NULL);
        R[i].need = 1;
        { int previous;
          for (previous = 0; previous < i; previous++) if (R[previous].need && !strcmp(R[previous].hex, R[i].hex)) break;
          if (previous == i) total += R[i].size; }
        nneed++;
    }
    if (nneed) {
        g_xferWhat = "Downloading"; g_xferDone = 0; g_xferTotal = total;
        xfer_show(1);
        for (i = 0; i < nr; i++) {
            wchar_t part[MAX_PATH * 2 + 24], dir[MAX_PATH * 2];
            char what[80], got[65] = "", hx[65];
            uint64_t sz;
            DWORD st, made;
            wchar_t *slash;
            if (!R[i].need) continue;
            { int prior;
              for (prior = 0; prior < i; prior++) if (!strcmp(R[prior].hex, R[i].hex) &&
                  sample_hash(R[prior].cache, hx, &sz) && sz == R[i].size && !strcmp(hx, R[i].hex)) break;
              if (prior < i) { map_set(R[i].p, R[prior].cache); ff_begin(R[i].p, R[i].hex, "download", R[i].size, "ready"); ff_finish("ready", "local_cache"); peer_offer(R[prior].cache, R[i].hex, R[i].size); continue; }
            }
            if (sample_hash(R[i].cache, hx, &sz) && sz == R[i].size && strcmp(hx, R[i].hex) == 0) {
                map_set(R[i].p, R[i].cache); ff_begin(R[i].p, R[i].hex, "download", R[i].size, "ready"); ff_finish("ready", "local_cache"); peer_offer(R[i].cache, R[i].hex, R[i].size); continue;
            }
            wcscpy_s(dir, MAX_PATH * 2, R[i].cache);
            slash = wcsrchr(dir, L'\\');
            ff_begin(R[i].p, R[i].hex, "download", R[i].size, "downloading");
            if (!slash) {sample_local_failed(); break;}
            *slash = 0; made = SHCreateDirectoryExW(NULL, dir, NULL);
            if ((made != ERROR_SUCCESS && made != ERROR_ALREADY_EXISTS && made != ERROR_FILE_EXISTS) ||
                !GetTempFileNameW(dir, L"flm", 0, part)) {sample_local_failed(); break;}
            sprintf_s(what, sizeof(what), "/blob/%s", R[i].hex);
            st = sample_http(L"GET", what, NULL, 0, NULL, 0, part, got, NULL, 0, R[i].size);
            if (st == 200 && session_current() && file_info(part, &sz, NULL) && sz == R[i].size && strcmp(got, R[i].hex) == 0) {
                if (!MoveFileExW(part, R[i].cache, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                    DeleteFileW(part); sample_local_failed(); break;
                }
                FILETIME mt;
                if (file_info(R[i].cache, &sz, &mt)) hash_put(R[i].cache, sz, mt, R[i].hex);
                map_set(R[i].p, R[i].cache);
                ff_finish("ready", "downloaded");
                peer_offer(R[i].cache, R[i].hex, R[i].size);
                downloaded++;
                logmsg("SAMPLES downloaded %S (%llu bytes)", R[i].cache, (unsigned long long)R[i].size);
            } else {
                DeleteFileW(part);
                if (g_sampleLocalError) sample_local_failed(); else sample_failed(st, st == 200 || g_sampleVerificationError);
                nfail++;
                logmsg("SAMPLES could not get %S (HTTP %lu%s): it will be missing", R[i].p, st, st == 200 ? ", content mismatch" : "");
                if (g_sampleRetry) break;
            }
        }
        xfer_end();
    }
    logmsg("SAMPLES op lists %d samples: %d downloaded, %d failed attempts%s", nr, downloaded, nfail, g_sampleRetry ? ", edit pending" : "");
    goto done;
invalid:
    sharing_fail("Sample metadata: session stopped", "The shared sample list is invalid, exceeds its limit, or could not fit in memory. Reconnect and resync before continuing to share.");
done:
    for (i = 0; i < nr; i++) free(R[i].p);
    free(R);
}

static int samples_prepare_receive(const char *msg) {
    unsigned attempt = 0;
    if (!session_current() || g_compatFault) return 0;
    do {
        g_sampleRetry = 0;
        samples_resolve(msg);
        if (!g_sampleRetry || !session_current() || g_compatFault) break;
        if (!sample_retry_wait(attempt)) break;
        if (attempt < 30) attempt++;
    } while (session_current());
    return session_current() && !g_compatFault;
}

static int message_has_samples(const char *m) {
    FlJson root = {m, strlen(m)}, op, value;
    return fj_member_is(root, "t", "\"op\"") && fj_get(root, "op", &op) && fj_get(op, "samples", &value);
}

// Every inbound message comes through here (receive thread).
static void inbox_msg(const char *m, LONG generation) {
    int queue, failed = 0;
    if (generation != g_netGen || g_compatFault) return;
    EnterCriticalSection(&g_inLock);
    queue = g_inBusy || g_inHead || message_has_samples(m) || fj_member_is((FlJson){m, strlen(m)}, "t", "\"stored\"");
    if (queue) {
        size_t bytes = strlen(m) + 1;
        InItem *it = NULL;
        if (g_inCount >= TRANSFER_QUEUE_MAX_COUNT || bytes > TRANSFER_QUEUE_MAX_BYTES - g_inBytes ||
            !(it = (InItem *)calloc(1, sizeof(InItem)))) failed = 1;
        else if (!(it->msg = _strdup(m))) { free(it); failed = 1; }
        else {
            it->gen = generation; it->bytes = bytes;
            if (g_inTail) g_inTail->next = it; else g_inHead = it;
            g_inTail = it; g_inBytes += bytes; g_inCount++;
        }
    }
    LeaveCriticalSection(&g_inLock);
    if (failed) sharing_fail("Download backlog: session stopped", "Shared edits exceeded the download backlog or available memory. Reconnect and resync before continuing to share.");
    else if (queue) SetEvent(g_inEvt);
    else handle_msg(m);
}

static DWORD WINAPI inThread(LPVOID p) {
    (void)p;
    for (;;) {
        WaitForSingleObject(g_inEvt, INFINITE);
        for (;;) {
            InItem *it;
            EnterCriticalSection(&g_inLock);
            it = g_inHead;
            if (!it) { g_inBusy = 0; LeaveCriticalSection(&g_inLock); break; }
            g_inHead = it->next;
            g_inBytes -= it->bytes; g_inCount--;
            if (!g_inHead) g_inTail = NULL;
            g_inBusy = 1;
            LeaveCriticalSection(&g_inLock);
            g_workBound = 1; g_workGen = it->gen;
            if (session_current() && fj_member_is((FlJson){it->msg, strlen(it->msg)}, "t", "\"stored\"")) {
                FlCloud ref; char *original = NULL, *merged = NULL, hx[65], what[80];
                if (g_cloudTransport && fc_reference(it->msg, &ref)) {
                    original = (char *)malloc(ref.size + 1);
                    sprintf_s(what, sizeof(what), "/blob/%s", ref.hash);
                    if (original && blob_http(L"GET", what, NULL, 0, NULL, 0, NULL, NULL, original, (int)ref.size + 1, 0) == 200 &&
                        session_current() && strlen(original) == ref.size && sha_hex(original, ref.size, hx) && !strcmp(hx, ref.hash))
                        merged = fc_merge(it->msg, original);
                }
                free(original);
                if (merged) { logmsg("CLOUD downloaded verified edit (%llu bytes)", (unsigned long long)ref.size); free(it->msg); it->msg = merged; }
                else if (session_current()) cloud_fail("A shared edit could not be downloaded or verified. Reconnect and resync before continuing to share.");
            }
            if (session_current() && !g_compatFault && message_has_samples(it->msg)) samples_prepare_receive(it->msg);
            if (session_current()) handle_msg(it->msg);
            free(it->msg); free(it);
            g_workBound = 0;
        }
    }
}

// Connected: where the blob store is (same server). Usable once the welcome brings the key.
static void samples_connected(const NetUrl *u) {
    InterlockedExchange(&g_peerReady, 0);
    InterlockedExchange64(&g_sampleBlockedUntil, 0);
    EnterCriticalSection(&g_sampleLock);
    g_blobUrl = *u;
    url_root(&g_blobUrl); // The private store routes by its generation-specific x-flim-key.
    g_blobKey[0] = 0;
    InterlockedExchange(&g_blobOn, 0);
    LeaveCriticalSection(&g_sampleLock);
}
// welcome: the session's key for the sample store (64 hex digits).
static void samples_key(const char *hex) {
    int i;
    for (i = 0; i < 64; i++) if (!isxdigit((unsigned char)hex[i])) return;
    EnterCriticalSection(&g_sampleLock);
    if (!session_current()) { LeaveCriticalSection(&g_sampleLock); return; }
    memcpy(g_blobKey, hex, 64);
    g_blobKey[64] = 0;
    InterlockedExchange(&g_blobOn, 1);
    LeaveCriticalSection(&g_sampleLock);
}
// Disconnected: drop what was waiting to go out or to be applied.
static void samples_disconnected(void) {
    int i;
    InterlockedExchange(&g_peerReady, 0);
    EnterCriticalSection(&g_sampleLock);
    InterlockedExchange(&g_blobOn, 0);
    SecureZeroMemory(g_blobKey, sizeof(g_blobKey));
    for (i = 0; i < g_npmap; i++) { free(g_pmap[i].from); free(g_pmap[i].to); }
    free(g_pmap); g_pmap = NULL; g_npmap = g_cappmap = 0;
    free(g_declined); g_declined = NULL; g_ndeclined = g_capdeclined = 0;
    LeaveCriticalSection(&g_sampleLock);
    EnterCriticalSection(&g_outLock);
    while (g_outHead) { OutItem *n = g_outHead->next; free(g_outHead->msg); free(g_outHead->blob); free(g_outHead); g_outHead = n; }
    g_outTail = NULL;
    g_outBytes = g_outCount = 0;
    LeaveCriticalSection(&g_outLock);
    EnterCriticalSection(&g_inLock);
    while (g_inHead) { InItem *n = g_inHead->next; free(g_inHead->msg); free(g_inHead); g_inHead = n; }
    g_inTail = NULL;
    g_inBytes = g_inCount = 0;
    LeaveCriticalSection(&g_inLock);
}

// ---------------- connection (one net thread per connect) ----------------
// net_connect starts a thread that opens the socket, hosts or joins a session and runs the
// receive loop. Each connect / disconnect bumps g_netGen; a thread whose generation is stale
// (the user disconnected or reconnected meanwhile) no longer touches the status.
typedef struct { LONG gen; int host; char url[512]; char pw[256]; char owner[256]; } NetReq;
static volatile LONG g_pollStarted = 0;

static void json_esc(const char *in, char *out, int cap) {
    int o = 0;
    for (; *in && o < cap - 7; in++) {
        unsigned char c = (unsigned char)*in;
        if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = (char)c; }
        else if (c < 0x20) o += sprintf_s(out + o, cap - o, "\\u%04x", c);
        else out[o++] = (char)c;
    }
    out[o] = 0;
}

// Forget every lock: they belong to the connection (the server drops them on disconnect).
static void net_reset(void) {
    int heldIndex;
    EnterCriticalSection(&g_qLock);
    g_npend = 0;
    LeaveCriticalSection(&g_qLock);
    EnterCriticalSection(&g_heldLock);
    for (heldIndex = 0; heldIndex < g_nheld; heldIndex++) free(g_held[heldIndex].msg);
    g_nheld = 0; g_heldBytes = 0;
    LeaveCriticalSection(&g_heldLock);
    proj_end();
    InterlockedExchange(&g_compatReady, 0);
    InterlockedExchange(&g_compatMixed, 0);
    InterlockedExchange(&g_portableSync, 0);
    InterlockedExchange(&g_portableLocal, 0);
    InterlockedExchange(&g_cloudTransport, 0);
    EnterCriticalSection(&g_netTextLock);
    g_nfocus = 0;                                         // where the others were: belongs to the session
    g_session[0] = 0;
    g_endsAt = 0;
    SecureZeroMemory(g_hostedText, sizeof(g_hostedText));
    SecureZeroMemory(g_hostPw, sizeof(g_hostPw));
    LeaveCriticalSection(&g_netTextLock);
    int i;
    InterlockedExchange(&g_isLeader, 0);
    EnterCriticalSection(&g_slotLock);
    for (i = 0; i < g_nslot; i++) {
        g_slots[i].lockedByMe = g_slots[i].lockedByPeer = 0;
        g_slots[i].hasUndo = 0; g_slots[i].undo = 0;
    }
    LeaveCriticalSection(&g_slotLock);
    EnterCriticalSection(&g_ulockLock);
    InterlockedExchange(&g_notesCrdt, 0);
    for (i = 0; i < MAX_PAT; i++) fnc_free(&g_noteSets[i]);
    g_noteSetCount = 0;
    for (i = 0; i < g_nulocks; i++) { g_ulocks[i].mine = g_ulocks[i].granted = g_ulocks[i].peer = 0; g_ulocks[i].owner[0] = 0; }
    g_peersJson[0] = 0;
    LeaveCriticalSection(&g_ulockLock);
}

static DWORD WINAPI netThread(LPVOID p) {
    NetReq *r = (NetReq *)p;
    NetUrl u;
    NetConn c;
    char err[200], name[2 * sizeof(g_myName)], pw[600], own[600], hello[2048], sess[FLIM_SESSION_CAP] = "", localFl[32];
    unsigned char *buf = NULL;
    size_t cap = 0, len = 0;
    g_workBound = 1; g_workGen = r->gen;

    if (r->host ? !parse_host(r->url, &u) : !parse_link(r->url, &u, sess)) {
        net_status(NET_ERR, r->host ? "Bad server address" : "Bad session link");
        goto done;
    }
    logmsg("NET connecting to %S (%s, port %u)", u.host, u.secure ? "wss" : "ws", u.port);
    if (!ws_open(&u, &c, err, sizeof(err))) {
        logmsg("NET connection failed: %s", err);
        if (r->gen == g_netGen) net_status(NET_ERR, "Can't connect: %s", err);
        goto done;
    }
    EnterCriticalSection(&g_lifecycleLock);
    EnterCriticalSection(&g_sendLock);
    if (r->gen != g_netGen) {                       // cancelled while connecting
        LeaveCriticalSection(&g_sendLock);
        LeaveCriticalSection(&g_lifecycleLock);
        net_close_handles(&c);
        goto done;
    }
    g_ws = c.ws;
    strcpy_s(g_netShown, sizeof(g_netShown), u.shown);
    strcpy_s(g_netRoot, sizeof(g_netRoot), u.shown);
    g_netUrl = u;
    g_netErr[0] = 0;
    InterlockedExchange(&g_hosting, r->host);
    EnterCriticalSection(&g_netTextLock);
    strcpy_s(g_hostPw, sizeof(g_hostPw), r->host ? r->pw : "");
    LeaveCriticalSection(&g_netTextLock);
    LeaveCriticalSection(&g_sendLock);
    InterlockedExchange(&g_compatFault, 0);
    samples_connected(&u);
    LeaveCriticalSection(&g_lifecycleLock);
    if (r->host) net_status(NET_CONNECTING, "Hosting on %s...", u.shown);
    else net_status(NET_CONNECTING, "Joining %s/%s...", u.shown, sess);

    if (!WideCharToMultiByte(CP_UTF8, 0, g_fl.build, -1, localFl, 32, NULL, NULL) || !flim_version_family(localFl)) {
        compat_fail("This FL build has no compatible wire profile."); goto done;
    }
    json_esc(g_myName, name, sizeof(name));
    json_esc(r->pw, pw, sizeof(pw));
    if (r->host) {
        json_esc(r->owner, own, sizeof(own));
        sprintf_s(hello, sizeof(hello),
            "{\"t\":\"host\",\"password\":\"%s\"%s%s%s,\"user\":{\"id\":\"%s\",\"name\":\"%s\"},\"transport\":2,\"notes_crdt\":1,\"portable_sync\":1,\"compat\":{\"protocol\":1,\"fl\":\"%s\",\"wire\":\"" FLIM_WIRE "\"}}",
            pw, own[0] ? ",\"owner\":\"" : "", own, own[0] ? "\"" : "", g_myId, name, localFl);
        SecureZeroMemory(own, sizeof(own));
        logmsg("NET hosting (reserved slot=%d)", r->owner[0] != 0);
    } else {
        sprintf_s(hello, sizeof(hello),
            "{\"t\":\"join\",\"session\":\"%s\",\"password\":\"%s\",\"user\":{\"id\":\"%s\",\"name\":\"%s\"},\"transport\":2,\"notes_crdt\":1,\"portable_sync\":1,\"compat\":{\"protocol\":1,\"fl\":\"%s\",\"wire\":\"" FLIM_WIRE "\"}}",
            sess, pw, g_myId, name, localFl);
        logmsg("NET joining as a member");
    }
    ws_send(hello);
    SecureZeroMemory(hello, sizeof(hello)); SecureZeroMemory(pw, sizeof(pw));
    if (!InterlockedExchange(&g_pollStarted, 1)) CreateThread(NULL, 0, pollThread, NULL, 0, NULL);

    for (;;) {
        DWORD got = 0, e;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE type;
        if (r->gen != g_netGen) break;
        if (!flim_ws_reserve(&buf, &cap, len)) {
            logmsg("NET receive buffer allocation failed");
            break;
        }
        e = WinHttpWebSocketReceive(c.ws, buf + len, (DWORD)(cap - len - 1), &got, &type);
        if (e) { logmsg("NET receive ended (%lu)", e); break; }
        if (type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
            USHORT code = 0; char reason[124] = { 0 }; DWORD rl = 0;
            WinHttpWebSocketQueryCloseStatus(c.ws, &code, reason, sizeof(reason) - 1, &rl);
            logmsg("NET server closed the connection (code=%u)", code);
            break;
        }
        if (r->gen != g_netGen) break;
        if (got > FLIM_WS_MAX_MESSAGE - len) {
            logmsg("NET message exceeds %u bytes", FLIM_WS_MAX_MESSAGE);
            WinHttpWebSocketShutdown(c.ws, WINHTTP_WEB_SOCKET_MESSAGE_TOO_BIG_CLOSE_STATUS, NULL, 0);
            break;
        }
        len += got;
        if (type == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE || type == WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE)
            continue;                               // more of the same message follows
        if (type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) { buf[len] = 0; inbox_msg((char *)buf, r->gen); }
        len = 0;
    }

    EnterCriticalSection(&g_lifecycleLock);
    EnterCriticalSection(&g_sendLock);
    if (g_ws == c.ws) g_ws = NULL;
    if (r->gen == g_netGen) {
        InterlockedIncrement(&g_netGen);
        LeaveCriticalSection(&g_sendLock);
        samples_disconnected();
        net_reset();
        if (g_netErr[0]) net_status(NET_ERR, "%s", g_netErr);
        else net_status(NET_ERR, "Connection to %s lost", u.shown);
    } else LeaveCriticalSection(&g_sendLock);
    LeaveCriticalSection(&g_lifecycleLock);
    net_close_handles(&c);
done:
    free(buf);
    SecureZeroMemory(r, sizeof(*r));
    free(r);
    return 0;
}

static void net_connect(const char *url, const char *pw, int host, const char *owner) {
    NetReq *r = (NetReq *)calloc(1, sizeof(NetReq));
    HANDLE th;
    if (!r) { net_status(NET_ERR, "Not enough memory to connect"); return; }
    EnterCriticalSection(&g_lifecycleLock);
    EnterCriticalSection(&g_sendLock);
    r->gen = InterlockedIncrement(&g_netGen);
    if (g_ws) { WinHttpWebSocketShutdown(g_ws, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0); g_ws = NULL; }
    InterlockedExchange(&g_compatReady, 0);
    LeaveCriticalSection(&g_sendLock);
    samples_disconnected(); net_reset();
    LeaveCriticalSection(&g_lifecycleLock);
    r->host = host;
    strncpy_s(r->url, sizeof(r->url), url, _TRUNCATE);
    strncpy_s(r->pw, sizeof(r->pw), pw ? pw : "", _TRUNCATE);
    strncpy_s(r->owner, sizeof(r->owner), owner ? owner : "", _TRUNCATE);
    {
        NetUrl u;
        if (parse_url(url, &u)) net_status(NET_CONNECTING, "Connecting to %s...", u.shown);
    }
    th = CreateThread(NULL, 0, netThread, r, 0, NULL);
    if (th) CloseHandle(th);
    else {
        SecureZeroMemory(r, sizeof(*r));
        free(r);
        net_status(NET_ERR, "Could not start the connection");
    }
}

// Main thread. Sends a close frame; the net thread sees the server's reply and cleans up.
static void net_disconnect(void) {
    EnterCriticalSection(&g_lifecycleLock);
    EnterCriticalSection(&g_sendLock);
    InterlockedIncrement(&g_netGen);
    if (g_ws) {
        WinHttpWebSocketShutdown(g_ws, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
        g_ws = NULL;
    }
    LeaveCriticalSection(&g_sendLock);
    samples_disconnected();
    net_reset();
    net_status(NET_OFF, "Not connected");
    LeaveCriticalSection(&g_lifecycleLock);
}

// ---------------- splash ----------------
// FL draws its startup fruit from <FL>\Artwork\Skins\Default\Title.png (read with CreateFileW
// right after TApplication is created). In this process only, that open is redirected to the
// bean (IDR_SPLASH, written to %TEMP%\flim\<pid>\splash.png). The file on disk is untouched,
// so FL started without flim keeps its own fruit. kernel32!CreateFileW is a "jmp [rip+x]" stub
// into kernelbase: we swap the stub's pointer slot (data, not code). It must be in place
// before FL's main thread runs, so it is installed from DllMain (the launcher resumes FL only
// once LoadLibrary has returned).
typedef HANDLE (WINAPI *createfilew_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static createfilew_t g_realCreateFileW = NULL;
static wchar_t g_splashPath[MAX_PATH];
static volatile LONG g_splashState = 0;        // 0 not written yet, 1 ready, -1 failed

static int splash_write(void) {
    HRSRC r = FindResourceW(g_hinst, MAKEINTRESOURCEW(IDR_SPLASH), (LPCWSTR)RT_RCDATA);
    HGLOBAL g = r ? LoadResource(g_hinst, r) : NULL;
    const void *data = g ? LockResource(g) : NULL;
    DWORD n = r ? SizeofResource(g_hinst, r) : 0, wrote = 0;
    wchar_t dir[MAX_PATH];
    HANDLE f;
    if (!data || !n) return 0;
    GetTempPathW(MAX_PATH, dir);
    wcscat_s(dir, MAX_PATH, L"flim");
    CreateDirectoryW(dir, NULL);
    swprintf_s(dir + wcslen(dir), MAX_PATH - wcslen(dir), L"\\%lu", GetCurrentProcessId());
    CreateDirectoryW(dir, NULL);
    swprintf_s(g_splashPath, MAX_PATH, L"%s\\splash.png", dir);
    f = g_realCreateFileW(g_splashPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    WriteFile(f, data, n, &wrote, NULL);
    CloseHandle(f);
    return wrote == n;
}

static int is_fl_title_png(LPCWSTR p) {
    static const wchar_t tail[] = L"\\Artwork\\Skins\\Default\\Title.png";
    size_t n, t = (sizeof(tail) / sizeof(wchar_t)) - 1;
    if (!p) return 0;
    n = wcslen(p);
    return n >= t && _wcsicmp(p + n - t, tail) == 0;
}

static HANDLE WINAPI hook_CreateFileW(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa,
                                      DWORD disp, DWORD flags, HANDLE tmpl) {
    if (g_splashState >= 0 && disp == OPEN_EXISTING && !(access & GENERIC_WRITE) && is_fl_title_png(name)) {
        if (g_splashState == 0) InterlockedExchange(&g_splashState, splash_write() ? 1 : -1);
        if (g_splashState == 1) {
            HANDLE h = g_realCreateFileW(g_splashPath, access, share, sa, disp, flags, tmpl);
            if (h != INVALID_HANDLE_VALUE) return h;
        }
    }
    return g_realCreateFileW(name, access, share, sa, disp, flags, tmpl);
}

static void splash_hook_install(void) {
    unsigned char *stub = (unsigned char *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CreateFileW");
    void **slot;
    DWORD old;
    if (!stub) return;
    if (stub[0] == 0x48) stub++;                                  // optional REX.W
    if (stub[0] != 0xFF || stub[1] != 0x25) return;               // not "jmp [rip+disp32]": keep FL's fruit
    slot = (void **)(stub + 6 + *(int32_t *)(stub + 2));
    if (!VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &old)) return;
    g_realCreateFileW = (createfilew_t)*slot;
    InterlockedExchangePointer(slot, (void *)hook_CreateFileW);
    VirtualProtect(slot, sizeof(void *), old, &old);
}

// ---------------- boot ----------------
static DWORD WINAPI engineMain(LPVOID p) {
    (void)p;
    srand(GetTickCount() ^ GetCurrentProcessId());
    logmsg("=== flim v." FLIM_VERSION " - engine v4.6 (desktop rooms + status + wss; params + plugin state + channels + native move + fx clear + notes + project files + playlist clips + unit locks + names/colors/routing + plugin locks + samples + markers/time signature + pattern markers/time signatures + pattern ops + plugin samples + focus) loaded ===");

    HMODULE fl = NULL;
    int tries;
    for (tries = 0; tries < 600 && !fl; tries++) { fl = GetModuleHandleW(FL_MODULE); if (!fl) Sleep(50); }
    if (!fl) { logmsg("FLEngine module not found"); return 0; }
    {   // which FL build: its row in k_flBuilds, or nothing (flim stays off, FL runs as usual)
        wchar_t path[MAX_PATH], ver[64] = L"?";
        DWORD h = 0, n;
        int i;
        GetModuleFileNameW(fl, path, MAX_PATH);
        n = GetFileVersionInfoSizeW(path, &h);
        if (n) {
            void *buf = malloc(n);
            VS_FIXEDFILEINFO *fi = NULL;
            UINT len = 0;
            if (buf && GetFileVersionInfoW(path, 0, n, buf) && VerQueryValueW(buf, L"\\", (void **)&fi, &len) && fi)
                swprintf_s(ver, 64, L"%u.%u.%u.%u", HIWORD(fi->dwFileVersionMS), LOWORD(fi->dwFileVersionMS),
                           HIWORD(fi->dwFileVersionLS), LOWORD(fi->dwFileVersionLS));
            free(buf);
        }
        static wchar_t profileBuild[32];
        wchar_t why[256];
        int profile = flim_profile_load(g_hinst, path, ver, &g_fl, profileBuild, why, 256);
        if (profile < 0) { logmsg("FL build %S: %S; flim stays off", ver, why); return 0; }
        if (!profile) for (i = 0; i < (int)(sizeof(k_flBuilds) / sizeof(k_flBuilds[0])); i++)
            if (wcscmp(k_flBuilds[i].build, ver) == 0) g_fl = k_flBuilds[i];
        if (!g_fl.build) { logmsg("FL build %S needs a verified compatibility profile: flim stays off", ver); return 0; }
        if (profile) logmsg("FL build %S: verified external compatibility profile (SHA-256 matched)", ver);
        logmsg("FL build %S: using its address table", ver);
    }
    g_flBase = (char *)fl;
    g_rec = (rec_t)(g_flBase + REC_RVA);
    g_setEnabled = (setenabled_t)(g_flBase + MUTE_RVA);
    g_savePreset = (presetfile_t)(g_flBase + (SAVEPRESET_VA - IMG_BASE));
    g_loadPreset = (presetfile_t)(g_flBase + (LOADPRESET_VA - IMG_BASE));
    g_hasPlugin  = (hasplugin_t)(g_flBase + (HASPLUGIN_VA - IMG_BASE));
    g_getPlugin  = (getplugin_t)(g_flBase + (GETPLUGIN_VA - IMG_BASE));
    g_intfClear  = (intfclear_t)(g_flBase + (INTFCLEAR_VA - IMG_BASE));
    g_addChannel = (addchan_t)(g_flBase + (ADDCHAN_VA - IMG_BASE));
    g_delChannel = (delchan_t)(g_flBase + (DELCHAN_VA - IMG_BASE));
    g_resolve    = (resolver_t)(g_flBase + (RESOLVER_VA - IMG_BASE));
    g_moveChans  = (movechan_t)(g_flBase + (MOVECHAN_VA - IMG_BASE));
    g_noteArr    = (notearr_t)(g_flBase + (NOTEARR_VA - IMG_BASE));
    g_noteDel    = (notedel_t)(g_flBase + (NOTEDEL_VA - IMG_BASE));
    g_gridRefresh = (gridrefresh_t)(g_flBase + (GRIDREFRESH_VA - IMG_BASE));
    logmsg("FLEngine base=%p rec=%p setEnabled=%p", (void *)fl, (void *)g_rec, (void *)g_setEnabled);
    logmsg("splash hook %s, splash %ld", g_realCreateFileW ? "on" : "OFF (kernel32 stub not recognised)", g_splashState);

    // per-process scratch dir for plugin state files
    GetTempPathA(MAX_PATH, g_tmpDir);
    strcat_s(g_tmpDir, MAX_PATH, "flim");
    CreateDirectoryA(g_tmpDir, NULL);
    sprintf_s(g_tmpDir + strlen(g_tmpDir), MAX_PATH - strlen(g_tmpDir), "\\%lu", GetCurrentProcessId());
    CreateDirectoryA(g_tmpDir, NULL);

    {
        char *slash;
        GetModuleFileNameA(NULL, g_fxDeletePreset, MAX_PATH);
        slash = strrchr(g_fxDeletePreset, '\\');
        if (slash) slash[1] = 0;
        strcat_s(g_fxDeletePreset, MAX_PATH, "Data\\System\\(delete) effect.fst");
        if (GetFileAttributesA(g_fxDeletePreset) == INVALID_FILE_ATTRIBUTES) logmsg("WARNING: %s not found", g_fxDeletePreset);
    }

    // Wait for the main window (FL fully booted), then hook its message loop.
    if (install_mainthread_hook() != 0) return 0;

    // FL loads the startup template a moment after its window appears, which
    // resets every param. Join only once params have been quiet for SETTLE_MS,
    // otherwise that reset would be taken for edits (or undo the joined state).
    {
        const DWORD SETTLE_MS = 3000, SETTLE_MAX_MS = 60000;
        DWORD start = GetTickCount(), quietSince;
        while (!fl_ready() && GetTickCount() - start < SETTLE_MAX_MS) Sleep(100);
        if (!fl_ready()) {
            logmsg("FL startup readiness timed out; native discovery and sharing remain disabled");
            return 0;
        }
        logmsg("FL ready after %lu ms", GetTickCount() - start);
        Sleep(500);
        quietSince = GetTickCount();
        rescan();
        while (GetTickCount() - quietSince < SETTLE_MS && GetTickCount() - start < SETTLE_MAX_MS) {
            Sleep(250);
            LONG before = g_nslot;
            int i, changed = 0;
            rescan();
            for (i = 0; i < g_nslot; i++) {
                uint32_t v = read_value(g_slots[i].id);
                if (v != g_slots[i].last) { g_slots[i].last = v; changed++; }
            }
            if (changed || g_nslot != before) quietSince = GetTickCount();
        }
        logmsg("settled after %lu ms (%ld params)", GetTickCount() - start, g_nslot);
        EnumWindows(findMainForm, (LPARAM)&g_mainForm);
        logmsg("main form %p", (void *)g_mainForm);
        patops_install();
        InterlockedExchange(&g_uiWanted, 1);
        PostMessageW(g_mainWnd, WM_NULL, 0, 0);
    }

    {   // who we are: flim.ini name (flim.exe's setup), FLIM_NAME overrides (dev: two FLs on one PC)
        wchar_t w[128], clean[FLIM_NAME_MAX + 1];
        char env[600] = "", pw[256] = "";
        DWORD nameSize = GetEnvironmentVariableW(L"FLIM_NAME", w, 128);
        if (!nameSize) flimcfg_get(L"name", w, 128);
        else if (nameSize >= 128) w[0] = 0;
        if (flim_sanitize_name(w, clean, FLIM_NAME_MAX + 1))
            WideCharToMultiByte(CP_UTF8, 0, clean, -1, g_myName, sizeof(g_myName), NULL, NULL);
        else sprintf_s(g_myName, sizeof(g_myName), "FL-%lu", GetCurrentProcessId());
        sprintf_s(g_myId, sizeof(g_myId), "fl-%lu-%u", GetCurrentProcessId(), (unsigned)rand());
        logmsg("I am %s (%s); waiting for the desktop room connection", g_myName, g_myId);

        // The desktop app passes connection details only to this FL process.
        DWORD urlSize = GetEnvironmentVariableA("FLIM_AUTOCONNECT", env, sizeof(env));
        if (urlSize >= sizeof(env)) env[0] = 0;
        else if (!urlSize) {
            char srv[256];
            DWORD serverSize = GetEnvironmentVariableA("FLIM_SERVER", srv, sizeof(srv));
            if (serverSize && serverSize < sizeof(srv)) sprintf_s(env, sizeof(env), "ws://%s", srv);
            else env[0] = 0;
        }
        if (env[0]) {
            char own[256] = "", hv[8] = "";
            DWORD hostSize = GetEnvironmentVariableA("FLIM_HOST", hv, sizeof(hv));
            DWORD passwordSize = GetEnvironmentVariableA("FLIM_PASSWORD", pw, sizeof(pw)), ownerSize = 0;
            int host = hostSize == 1 && hv[0] == '1';
            if (host) ownerSize = GetEnvironmentVariableA("FLIM_OWNER_KEY", own, sizeof(own));
            if (hostSize < sizeof(hv) && passwordSize < sizeof(pw) && ownerSize < sizeof(own)) net_connect(env, pw, host, own);
            else net_status(NET_ERR, "Desktop connection details are too long");
            SecureZeroMemory(pw, sizeof(pw)); SecureZeroMemory(own, sizeof(own));
        }
    }
    // This thread installed the main-thread hooks, and Windows removes a hook when the
    // thread that set it exits: it must stay alive for as long as FL runs.
    for (;;) Sleep(INFINITE);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_hinst = h;
        DisableThreadLibraryCalls(h);
        splash_hook_install();
        InitializeCriticalSection(&g_sendLock);
        InitializeCriticalSection(&g_slotLock);
        InitializeCriticalSection(&g_qLock);
        InitializeCriticalSection(&g_lifecycleLock);
        InitializeCriticalSection(&g_heldLock);
        InitializeCriticalSection(&g_ulockLock);
        InitializeCriticalSection(&g_netTextLock);
        InitializeCriticalSection(&g_sampleLock);
        InitializeCriticalSection(&g_outLock);
        InitializeCriticalSection(&g_inLock);
        g_outEvt = CreateEventW(NULL, FALSE, FALSE, NULL);
        g_inEvt = CreateEventW(NULL, FALSE, FALSE, NULL);
        {
            char v[8];
            g_noLocal = GetEnvironmentVariableA("FLIM_SAMPLE_NOLOCAL", v, sizeof(v)) && v[0] == '1';
            g_curNoCover = GetEnvironmentVariableA("FLIM_CURSOR_NOCOVER", v, sizeof(v)) && v[0] == '1';
        }
        CreateThread(NULL, 0, outThread, NULL, 0, NULL);
        CreateThread(NULL, 0, inThread, NULL, 0, NULL);
        CreateThread(NULL, 0, engineMain, NULL, 0, NULL);
    }
    return TRUE;
}
