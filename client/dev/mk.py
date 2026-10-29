# Helpers for poking at FL's state through the probe (see README.md). A, B = the pids of the
# leader and member FL started by restart_test.ps1, read from the engine log. Addresses and offsets
# come from the engine's per-build table (flbuild.py), so this works with every supported FL build.
import fl, flbuild, struct, sys, os, re

def session_pids(log=os.path.join(os.environ['TEMP'], 'flim_engine.log')):
    # the test FLs are named A (leader) and B (member) by restart_test.ps1 / restart_dev.ps1
    t = open(log, encoding='utf-8', errors='replace').read()
    pid = lambda name: int(re.findall(r'\[(\d+)\] I am %s \(fl-' % name, t)[-1])
    return pid('A'), pid('B')

try: A, B = session_pids()
except (OSError, IndexError): A = B = None
def V(p): return flbuild.build(p.pid)
def marks(p):
    v = V(p)
    PL = p.q(p.g(v.PLFORM)); L = p.q(PL + v.PL_MARKERS); a = p.q(L)
    n = p.q(a - 8) if a else 0
    out = []
    for i in range(n):
        r = p.r(a + i * 0x34, 0x34)
        out.append((struct.unpack('<i', r[0:4])[0], struct.unpack('<i', r[4:8])[0], p.ustr(struct.unpack('<Q', r[8:16])[0]), r[16:].hex()))
    return out
def ts(p): v = V(p); return p.d(p.g(v.TSNUM)), p.d(p.g(v.TSDEN))
def chans(p):
    lst = p.q(p.g(V(p).CHANLIST)); items = p.q(lst + 8); n = p.d(lst + 0x10)
    return [(i, p.ustr(p.q(p.q(items + 8 * i) + 0x50))) for i in range(n)]
def pats(p, n=6):
    v = V(p); tbl = p.g(v.PATARR); out = []
    for i in range(1, n + 1):
        r = tbl + i * v.PAT_STRIDE
        na = p.q(r + 0x28); cnt = p.d(na + 0x14) if na else 0
        out.append((i, p.ustr(p.q(r)), cnt))
    return out
def patop(p, slot, *args):
    proj = p.q(p.q(p.g(V(p).FLPROJ)) + 0x10); vmt = p.q(proj)
    fn = p.q(vmt + slot)
    r = p.cmd('call %x %d %s' % (fn, proj, ' '.join('%d' % (x & 0xFFFFFFFFFFFFFFFF) for x in args)))
    return r
def setup(a):
    v = V(a)
    for pat, nm in ((1, 'Verse'), (2, 'Chorus'), (3, 'Bridge')):
        a.call(v.PATNAME, pat, a.mkstr(nm))
        arr = a.call(v.NOTEARR, pat, 1)
        rec = a.alloc(24)
        a.w(rec, struct.pack('<IHHIHHBBBBBBBB', 0, 0x4000, 0, 96 * pat, 60 + pat, 0, 120, 0, 64, 0, 64, 100, 128, 128))
        a.cmd('call %x %d %d' % (a.q(a.q(arr) + 8), arr, rec))
def pmarks(p, pat):
    # pattern pat's markers (piano roll): [(pos, action, name, tail hex)]; time signature = action 8, tail[0:2] = num, den
    v = V(p)
    L = p.q(p.g(v.PATARR) + pat * v.PAT_STRIDE + 0x30)
    n = p.q(L - 8) if L else 0
    out = []
    for i in range(n):
        r = p.r(L + i * 0x34, 0x34)
        out.append((struct.unpack('<i', r[0:4])[0], struct.unpack('<i', r[4:8])[0], p.ustr(struct.unpack('<Q', r[8:16])[0]), r[16:].hex()))
    return out
def show(p, wid):
    # ui.showWindow(wid) natively: 0 mixer, 1 channel rack, 2 playlist, 3 piano roll, 4 browser
    o = p.q(p.g(V(p).FLPROJ)); iface = p.q(o + 0x54)
    return p.cmd('call %x %d %d 1' % (p.q(p.q(iface)), iface, wid))
def pr_add_marker(p, pos, action, num=4, den=4):
    # what the piano roll does after its marker dialog (on the pattern it shows; open it with show(p, 3))
    v = V(p)
    pr = p.q(p.g(v.PRFORM))
    return p.cmd('call %x %d %d 0 %d %d %d' % (p.a(v.FORMADDMARK), pr, pos, action, num, den))
