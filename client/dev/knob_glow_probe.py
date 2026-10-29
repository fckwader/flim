# Knob glow probe: B is shown maximized with the mixer (or channel rack) in front; A turns a knob there;
# B's window is captured while the frame glows and again once it has faded. Uses real window focus on B.
#   py -3.11 knob_glow_probe.py [mixer|rack|plug] (plug: Serum on channel 4, its window open in B)
import fl, mk, stress, os, sys, time, ctypes, ctypes.wintypes as W

WIN = {'mixer': 0, 'rack': 1, 'plug': None}
ID = {'mixer': 0x70401fc0,        # mixer track 1 volume
      'rack': 0x00000000,         # channel 0 volume
      'plug': (4 << 16) + 0x8000}  # channel 4's plugin, parameter 0


def shot(hwnd, path):
    r = W.RECT(); fl.u32.GetWindowRect(hwnd, ctypes.byref(r))
    fl.screenshot(path, (r.left, r.top, r.right - r.left, r.bottom - r.top))
    return path


if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'mixer'
    A, B = stress.Side('A', mk.A), stress.Side('B', mk.B)
    hb = [h for p, h, c, t in fl.windows([mk.B]) if c == 'TFruityLoopsMainForm'][0]
    fl.u32.ShowWindow(hb, 3); fl.u32.SetForegroundWindow(hb); time.sleep(1.0)
    if WIN[mode] is not None: mk.show(B.p, WIN[mode]); time.sleep(1.5)
    out = os.environ['TEMP']
    v = A.rec(ID[mode])
    for k in range(5):
        A.rec(ID[mode], (v + 700 * (k + 1)) % (65536 if mode == 'plug' else 12800))
        time.sleep(0.05)
    time.sleep(0.4)
    print(shot(hb, os.path.join(out, 'kglow_%s_on.png' % mode)))
    time.sleep(2.0)
    print(shot(hb, os.path.join(out, 'kglow_%s_off.png' % mode)))
    A.rec(ID[mode], v)
