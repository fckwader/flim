# Plugin knob probe: B turns knobs of the plugin on channel <ch> for a while (both sides "active");
# a healthy session sends only param.set ops: no plug.state, no whole-plugin loads.
#   py -3.11 serum_probe.py <ch> [seconds]
import fl, mk, sync_probe as sp, random, sys, threading, time

if __name__ == '__main__':
    ch = int(sys.argv[1]); secs = float(sys.argv[2]) if len(sys.argv) > 2 else 10
    for pid in (mk.A, mk.B): fl.inject(pid)
    a, b = fl.Probe(mk.A), fl.Probe(mk.B); v = mk.V(b)
    stop = threading.Event()
    for pid in (mk.A, mk.B): threading.Thread(target=sp.keepalive, args=(pid, stop), daemon=True).start()
    ids = [(ch << 16) | (0x8000 + p) for p in range(40)]
    ids = [i for i in ids if b.call(v.REC, i, 0, 2) != 0xFFFFFFFF][:20]
    print('plugin params found:', len(ids))
    sp.mark('B turns %d knobs of ch %d for %.0f s' % (len(ids), ch, secs))
    t_end = time.time() + secs; last = {}
    while time.time() < t_end:
        i = random.choice(ids)
        last[i] = b.call(v.REC, i, random.randint(0, 65535), 1 | 16) and b.call(v.REC, i, 0, 2)
        time.sleep(0.05)
    time.sleep(4)
    bad = [hex(i) for i, val in last.items() if a.call(v.REC, i, 0, 2) != val]
    print('knobs that differ on A:', bad or 'none')
    stop.set(); sp.mark('serum done')
