# Echo probe: does B send back a whole channel state after it applied A's knob / name change?
#   py -3.11 echo_probe.py
import fl, mk, sync_probe as sp, threading, time

if __name__ == '__main__':
    for pid in (mk.A, mk.B): fl.inject(pid)
    a = fl.Probe(mk.A); v = mk.V(a)
    stop = threading.Event()
    threading.Thread(target=sp.keepalive, args=(mk.B, stop), daemon=True).start()
    sp.mark('B active 15 s: baselines'); time.sleep(15)
    sp.mark('A: channel 3 volume (B keeps being active)')
    a.call(v.REC, (3 << 16) | 0, 4321, 1 | 16)
    time.sleep(20)
    stop.set()
    sp.mark('done')
