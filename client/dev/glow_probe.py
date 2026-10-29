# Glow probe: B shows the piano roll (F7) or playlist (F5) maximized; A adds notes (or clips); B's window
# is captured right after they arrive and again once the glow has faded. Uses real key presses on B.
#   py -3.11 glow_probe.py [pr|pl]
import fl, mk, stress, os, sys, time, ctypes, ctypes.wintypes as W

VK = {'pr': 0x76, 'pl': 0x74}     # F7 piano roll, F5 playlist


def shot(hwnd, path):
    r = W.RECT(); fl.u32.GetWindowRect(hwnd, ctypes.byref(r))
    fl.screenshot(path, (r.left, r.top, r.right - r.left, r.bottom - r.top))
    return path


def key(vk):
    fl.u32.keybd_event(vk, 0, 0, 0); time.sleep(0.05); fl.u32.keybd_event(vk, 0, 2, 0)


if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'pr'
    base = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    A, B = stress.Side('A', mk.A), stress.Side('B', mk.B)
    hb = [h for p, h, c, t in fl.windows([mk.B]) if c == 'TFruityLoopsMainForm'][0]
    fl.u32.ShowWindow(hb, 3); fl.u32.SetForegroundWindow(hb); time.sleep(1.0)
    key(VK[mode]); time.sleep(1.5)
    out = os.environ['TEMP']
    if mode == 'pr':
        for k in range(6): A.add_note(1, base + 96 * k, 60 + k, 0)
    else:
        for k in range(4): A.add_clip(base + 192 * k, 1 + k)
    time.sleep(1.0)
    print(shot(hb, os.path.join(out, 'glow_%s_on.png' % mode)))
    time.sleep(2.0)
    print(shot(hb, os.path.join(out, 'glow_%s_off.png' % mode)))
