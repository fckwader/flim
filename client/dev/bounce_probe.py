# Sample bounce probe (B started with FLIM_SAMPLE_NOLOCAL=1, restart_dev.ps1 -NoLocalB): A adds a
# channel holding a sample; both sides keep "using" FL for a while. A healthy session sends the
# channel once (chan.add); a bounce shows as repeated plug.state sends / applies of that channel.
#   py -3.11 bounce_probe.py
import fl, mk, sync_probe as sp, os, threading, time

if __name__ == '__main__':
    for pid in (mk.A, mk.B): fl.inject(pid)
    a = fl.Probe(mk.A); v = mk.V(a)
    lst = a.q(a.g(v.CHANLIST))
    src = a.q(a.q(lst + 8))                                   # channel 0: a Sampler with a sample
    fst = os.path.join(os.environ['TEMP'], 'flim_bounce_src.fst')
    if os.path.exists(fst): os.remove(fst)
    a.call(v.SAVEPRESET, a.mkstr(fst), 32, src, 1)
    stop = threading.Event()
    for pid in (mk.A, mk.B): threading.Thread(target=sp.keepalive, args=(pid, stop), daemon=True).start()
    sp.mark('both active 12 s: baselines'); time.sleep(12)
    sp.mark('A: new channel with a sample')
    last = a.d(lst + 0x10)
    a.call(v.ADDCHAN, 0xFFFFFFFFFFFFFFFF, 0, 1)
    ch = a.q(a.q(lst + 8) + 8 * last)
    a.call(v.LOADPRESET, a.mkstr(fst), 32, ch, 0)
    time.sleep(40)
    stop.set()
    sp.mark('done')
