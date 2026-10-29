# Redundant-send probe for a two-FL session (A leads, B joins; restart_test.ps1 or the same by hand).
# Makes small edits in A through FL's own functions and writes "=== STEP" markers into the engine
# log, so the DIFF / PLUG lines of each step can be read back. A keep-alive thread posts harmless
# key-up messages to A's main form: the engine only sweeps / sends while someone "uses" FL.
#   py -3.11 sync_probe.py [steps...]      steps: idle select volume add sampleidle
import fl, mk, ctypes, os, struct, sys, threading, time

LOG = os.path.join(os.environ['TEMP'], 'flim_engine.log')
WM_KEYUP, VK_SHIFT = 0x101, 0x10


def mark(text):
    with open(LOG, 'a', encoding='utf-8') as f:
        f.write('%s [probe] === STEP %s\n' % (time.strftime('%H:%M:%S.000'), text))
    print('---', text, flush=True)


def main_form(pid):
    for p, h, c, t in fl.windows([pid]):
        if c == 'TFruityLoopsMainForm': return h
    return None


def keepalive(pid, stop):
    h = main_form(pid)
    while not stop.is_set():
        if h: fl.u32.PostMessageW(h, WM_KEYUP, VK_SHIFT, 0xC02A0001)
        time.sleep(0.8)


def chan_obj(p, i):
    lst = p.q(p.g(mk.V(p).CHANLIST))
    return p.q(p.q(lst + 8) + 8 * i)


def step_idle(a, b, v):
    mark('idle (input only, no edits)'); time.sleep(12)


def step_select(a, b, v):
    mark('select channel 1 (selection byte)')
    ch = chan_obj(a, 1)
    cur = a.r(ch + v.CH_SELECTED, 1)[0]
    a.w(ch + v.CH_SELECTED, bytes([0 if cur else 1]))
    time.sleep(10)


def step_volume(a, b, v):
    mark('channel 2 volume via REC')
    a.call(v.REC, (2 << 16) | 0, 9000, 1 | 16)
    time.sleep(8)
    print('   B ch2 volume:', b.call(v.REC, (2 << 16) | 0, 0, 2))


def step_add(a, b, v):
    mark('add a channel')
    a.call(v.ADDCHAN, 0xFFFFFFFFFFFFFFFF, 0, 1)
    time.sleep(20)


STEPS = {'idle': step_idle, 'select': step_select, 'volume': step_volume, 'add': step_add,
         'sampleidle': step_idle}

if __name__ == '__main__':
    names = sys.argv[1:] or ['idle', 'select', 'volume', 'add', 'sampleidle']
    for pid in (mk.A, mk.B): fl.inject(pid)
    a, b = fl.Probe(mk.A), fl.Probe(mk.B)
    v = mk.V(a)
    stop = threading.Event()
    threading.Thread(target=keepalive, args=(mk.A, stop), daemon=True).start()
    try:
        for n in names: STEPS[n](a, b, v)
    finally:
        stop.set()
        mark('done')
