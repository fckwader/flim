# Tempo scroll probe: A steps the tempo 130 -> 140 BPM quickly (like a mouse-wheel scroll); B must
# end at 140, and the engine should send far fewer than 10 updates.   py -3.11 tempo_probe.py
import fl, mk, sync_probe as sp, time

TEMPO = 0x40000005

if __name__ == '__main__':
    for pid in (mk.A, mk.B): fl.inject(pid)
    a, b = fl.Probe(mk.A), fl.Probe(mk.B); v = mk.V(a)
    a.call(v.REC, TEMPO, 130000, 1 | 16); time.sleep(2.5)
    sp.mark('tempo scroll 130 -> 140')
    for bpm in range(131, 141):
        a.call(v.REC, TEMPO, bpm * 1000, 1 | 16)
        time.sleep(0.02)
    time.sleep(2.5)
    got = b.call(v.REC, TEMPO, 0, 2)
    print('B tempo', got / 1000, 'PASS' if got == 140000 else 'FAIL')
    sp.mark('tempo done')
