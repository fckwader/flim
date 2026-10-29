# Save a channel's state (FL's preset saver, what the engine sends) before / after an action in FL,
# and print which FLP events changed.   py -3.11 state_diff.py <pid> <channel> <action>
#   actions: select (toggle selected byte), add (append a channel), vol (set its volume),
#            none (save twice: is the state stable?)
import fl, mk, flp, os, sys, time

MASK_CHAN = 32


def save(p, v, ch, path):
    if os.path.exists(path): os.remove(path)
    obj = p.q(p.q(p.q(p.g(v.CHANLIST)) + 8) + 8 * ch)
    r = p.call(v.SAVEPRESET, p.mkstr(path), MASK_CHAN, obj, 1)
    d = open(path, 'rb').read()
    return r, d


def diff(a, b):
    ea, eb = flp.events(a), flp.events(b)
    print('events %d -> %d, bytes %d -> %d' % (len(ea), len(eb), len(a), len(b)))
    for i, ((ia, va), (ib, vb)) in enumerate(zip(ea, eb)):
        if ia != ib: print('  #%d id %d -> %d: out of step' % (i, ia, ib)); return
        if va != vb:
            k = next((k for k in range(min(len(va), len(vb))) if va[k] != vb[k]), min(len(va), len(vb)))
            print('  #%d ev%d len %d->%d first diff @%d: %s -> %s' % (i, ia, len(va), len(vb), k, va[k:k+16].hex(), vb[k:k+16].hex()))


if __name__ == '__main__':
    pid, ch, action = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
    fl.inject(pid)
    p = fl.Probe(pid); v = mk.V(p)
    tmp = os.environ['TEMP']
    _, before = save(p, v, ch, os.path.join(tmp, 'sd_before.fst'))
    obj = p.q(p.q(p.q(p.g(v.CHANLIST)) + 8) + 8 * ch)
    if action == 'select':
        cur = p.r(obj + v.CH_SELECTED, 1)[0]; p.w(obj + v.CH_SELECTED, bytes([0 if cur else 1]))
    elif action == 'add':
        p.call(v.ADDCHAN, 0xFFFFFFFFFFFFFFFF, 0, 1)
    elif action == 'vol':
        p.call(v.REC, (ch << 16) | 0, 7777, 1 | 16)
    time.sleep(0.5)
    _, after = save(p, v, ch, os.path.join(tmp, 'sd_after.fst'))
    diff(before, after)
