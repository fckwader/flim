# Heavy two-person usage + drop measurement (A and B from restart_test.ps1 / restart_dev.ps1).
# Rounds: both sides edit at the same time for BURST s (knobs: channel vol/pan, mixer vol, effect
# params; notes; playlist clips), then everything settles for SETTLE s and each edit of the round is
# checked on both sides:
#   uncontested edit (only one side touched that knob / pattern / playlist this round):
#       DROP if its value / note / clip is not on both sides
#   contested (both touched it): DIVERGED if A and B differ; LOST if the final value is neither side's
# Two phases: "separate" (each side its own channels' knobs, effect, patterns; the playlist is
# shared) and "shared" (random targets from one pool).  Engine log events are counted per phase.
#   py -3.11 stress.py [label] [rounds per phase]
import fl, mk, sync_probe as sp, os, random, re, struct, sys, threading, time, json

BURST, SETTLE, KNOB_GAP = 1.6, 4.5, 0.11
LOG = sp.LOG
FL_DIR = r'C:\Program Files (x86)\Image-Line\FL Studio 2025'
FX_PRESET = FL_DIR + r'\Data\Patches\Plugin presets\Effects\Fruity Delay 3\Chorus.fst'
MASK_FX = 48


def MIX_ID(t, sub): return 0x70000000 + (t << 22) + sub
def FX_ID(t, slot, p): return 0x70000000 + (((t << 6) | slot) << 16) + 0x8000 + p


class Side:
    def __init__(self, name, pid):
        fl.inject(pid)
        self.name, self.pid, self.p = name, pid, fl.Probe(pid)
        self.v = mk.V(self.p)
        self.lock = threading.Lock()

    def rec(self, id_, val=None):
        with self.lock:
            if val is None: return self.p.call(self.v.REC, id_, 0, 2)
            self.p.call(self.v.REC, id_, val, 1 | 16)
            return self.p.call(self.v.REC, id_, 0, 2)          # what FL took (clamped / quantized)

    def notes(self, pat):
        with self.lock:
            p = self.p
            na = p.q(p.g(self.v.PATARR) + pat * self.v.PAT_STRIDE + 0x28)
            if not na: return set()
            n = p.d(na + 0x14)
            if not n: return set()
            raw = p.r(p.q(na + 8), n * 24)
            return {(struct.unpack_from('<I', raw, i * 24)[0], struct.unpack_from('<H', raw, i * 24 + 12)[0]) for i in range(n)}

    def add_note(self, pat, pos, pitch, chan=0):
        with self.lock:
            p = self.p
            arr = p.call(self.v.NOTEARR, pat, 1)
            rec = p.alloc(24)
            p.w(rec, struct.pack('<IHHIHHBBBBBBBB', pos, 0x4000, chan, 48, pitch, 0, 120, 0, 64, 0, 64, 100, 128, 128))
            p.cmd('call %x %d %d' % (p.q(p.q(arr) + 8), arr, rec))

    def clip_arr(self):
        p = self.p
        arrs = p.g(self.v.ARRS)
        return p.q(p.q(arrs + 8 * p.d(p.a(self.v.ARRCUR))) + 0x14)

    def clips(self):
        with self.lock:
            p = self.p
            ca = self.clip_arr(); n = p.d(ca + 0x14)
            if not n: return set()
            raw = p.r(p.q(ca + 8), n * 0x50)
            return {struct.unpack_from('<I', raw, i * 0x50)[0] for i in range(n)
                    if struct.unpack_from('<i', raw, i * 0x50 + 4)[0] != -1}

    def add_clip(self, pos, track):
        with self.lock:
            p = self.p
            rec = bytearray(0x50)
            struct.pack_into('<IHHIHHHHIff', rec, 0, pos, 0x5000, 0x5000 + 1, 96, 499 - track, 0, 0, 0x40, 0, -1.0, -1.0)
            buf = p.alloc(0x50); p.w(buf, bytes(rec))
            ca = self.clip_arr()
            p.cmd('call %x %d %d' % (p.q(p.q(ca) + 8), ca, buf))
            p.call(self.v.PLREFRESH, p.q(p.g(self.v.PLFORM)))

    def nchan(self):
        with self.lock:
            return self.p.d(self.p.q(self.p.g(self.v.CHANLIST)) + 0x10)

    def add_fx(self, track):
        with self.lock:
            p = self.p
            mix = p.g(self.v.MIXARR) + track * 0x1474
            p.call(self.v.LOADPRESET, p.mkstr(FX_PRESET), MASK_FX, p.q(mix + 0x1324), 0)


def log_counts(t0, t1, pids):
    pats = {'snapped back': r'snapped back', 'lock reverted': r'local change reverted',
            'unsent edit replaced': r'unsent edit was replaced', 'revert to agreed': r'reverting to the agreed',
            'plug.state sent': r'PLUG sent plug\.state', 'whole-state loads': r'PLUG applied', 'DIFF': r'\] DIFF ',
            'remote absorbed': r'remote change absorbed', 'drift absorbed': r'drift absorbed', 'SLOW': r'\] SLOW ',
            'lock denied': r'LOCK .* denied', 'send failed': r'send failed', 'disconnect': r'NET (server closed|Not connected)'}
    out = {k: 0 for k in pats}
    with open(LOG, encoding='utf-8', errors='replace') as f:
        for line in f:
            m = re.match(r'(\d\d):(\d\d):(\d\d)\.(\d+) \[(\d+)\]', line)
            if not m or int(m.group(5)) not in pids: continue
            ts = int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3)) + int(m.group(4)) / 1000
            if not (t0 <= ts <= t1): continue
            for k, pat in pats.items():
                if re.search(pat, line): out[k] += 1
    return out


def clock(): t = time.localtime(); return t.tm_hour * 3600 + t.tm_min * 60 + t.tm_sec + (time.time() % 1)


def actor(side, plan, edits, stop_at):
    """side does plan[] (list of (kind, args)) spread over the burst; records what it did"""
    for kind, args in plan:
        if time.time() > stop_at: break
        try:
            if kind == 'knob':
                got = side.rec(args[0], args[1])
                edits.append(('knob', args[0], side.name, time.time(), got))
            elif kind == 'note':
                side.add_note(*args)
                edits.append(('note', args, side.name, time.time(), None))
            elif kind == 'clip':
                side.add_clip(*args)
                edits.append(('clip', args, side.name, time.time(), None))
        except Exception as e:
            edits.append(('error', repr(e), side.name, time.time(), None))
        time.sleep(KNOB_GAP * random.uniform(0.6, 1.4))


def run_phase(A, B, phase, rounds, res):
    nch = min(A.nchan(), B.nchan())
    chans = list(range(min(nch, 6)))
    ch_ids = [(c << 16) | s for c in chans for s in (0, 1)]
    mix_ids = [MIX_ID(t, 0x1fc0) for t in range(1, 7)]
    fx_ids = {1: [FX_ID(1, 0, p) for p in range(6)], 2: [FX_ID(2, 0, p) for p in range(6)]}
    seq = [0]
    for r in range(rounds):
        plans = {}
        for s, side in enumerate((A, B)):
            if phase == 'separate':
                pool = [i for k, i in enumerate(ch_ids) if (k // 2) % 2 == s] + mix_ids[s::2] + fx_ids[1 + s]
                pats = [1, 2]                     # same patterns, each side its own instrument
                chs = [s]
                trks = [10 + s]
            else:
                pool = ch_ids + mix_ids + fx_ids[1] + fx_ids[2]
                pats = [1, 2, 3]
                chs = [0, 1, 2]
                trks = [10, 11, 12]
            plan = []
            for k in range(int(BURST / KNOB_GAP)):
                plan.append(('knob', (random.choice(pool), None)))
            for k in range(2):
                seq[0] += 1
                plan.insert(random.randrange(len(plan)), ('note', (random.choice(pats), 4000 + seq[0] * 48 + s * 24, 50 + seq[0] % 30, random.choice(chs))))
            if random.random() < 0.5:
                seq[0] += 1
                plan.insert(random.randrange(len(plan)), ('clip', (20000 + seq[0] * 96 + s * 48, random.choice(trks))))
            plans[side.name] = plan
        # knob values: random, decided now (value None -> random within a safe range)
        for side in (A, B):
            plans[side.name] = [(k, (a[0], random.randint(500, 12000))) if k == 'knob' else (k, a) for k, a in plans[side.name]]
        edits = []
        stop_at = time.time() + BURST + 1.0
        th = [threading.Thread(target=actor, args=(side, plans[side.name], edits, stop_at)) for side in (A, B)]
        for t in th: t.start()
        for t in th: t.join()
        time.sleep(SETTLE)
        check_round(A, B, edits, res)
        print('  %s round %d/%d: %s' % (phase, r + 1, rounds, {k: v for k, v in res.items() if v}), flush=True)


def check_round(A, B, edits, res):
    side = {'A': A, 'B': B}
    knobs = {}
    for kind, tgt, who, ts, got in edits:
        if kind == 'error': res['probe errors'] += 1; continue
        if kind == 'knob': knobs.setdefault(tgt, []).append((ts, who, got))
    plug_whos = {}                                   # effect plugin (track, slot) -> sides that touched it
    for tgt, ev in knobs.items():
        if tgt >= 0x70000000 and (tgt & 0xFFFF) >= 0x8000:
            plug_whos.setdefault(tgt >> 16, set()).update(w for _, w, _ in ev)
    for tgt, ev in knobs.items():
        ev.sort()
        a, b = A.rec(tgt), B.rec(tgt)
        whos = {w for _, w, _ in ev}
        res['knob edits'] += len(ev); res['knobs checked'] += 1
        if len(whos) == 1:
            want = ev[-1][2]
            if a != want or b != want:
                same_plugin = len(plug_whos.get(tgt >> 16, ())) > 1
                k = 'knob DROP (other side on same effect)' if same_plugin else 'knob DROP (uncontested)'
                res[k] += 1
                if res[k] <= 4: print('    %s %#x by %s: want %d, A %d B %d' % (k, tgt, ev[-1][1], want, a, b))
        else:
            res['knobs contested'] += 1
            lastA = [g for _, w, g in ev if w == 'A'][-1]; lastB = [g for _, w, g in ev if w == 'B'][-1]
            if a != b: res['knob DIVERGED'] += 1
            elif a not in (lastA, lastB): res['knob LOST (contested)'] += 1
    # notes per pattern
    by_pat = {}
    for kind, tgt, who, ts, got in edits:
        if kind == 'note': by_pat.setdefault(tgt[0], []).append((tgt[1], tgt[2], who, tgt[3]))
    for pat, ns in by_pat.items():
        na, nb = A.notes(pat), B.notes(pat)
        for pos, pitch, who, ch in ns:
            contested = len({w for _, _, w, c in ns if c == ch}) > 1      # both on this pattern + channel
            res['notes added'] += 1
            if (pos, pitch) not in na or (pos, pitch) not in nb:
                res['note DROP (contested pattern+channel)' if contested else 'note DROP (uncontested)'] += 1
        if na != nb: res['pattern DIVERGED'] += 1
    # clips
    cl = [(tgt, who) for kind, tgt, who, ts, got in edits if kind == 'clip']
    if cl:
        ca, cb = A.clips(), B.clips()
        for (pos, trk), who in cl:
            contested = len({w for (_, t), w in cl if t == trk}) > 1      # both on this track
            res['clips added'] += 1
            if pos not in ca or pos not in cb:
                res['clip DROP (contested track)' if contested else 'clip DROP (uncontested)'] += 1
        if ca != cb: res['playlist DIVERGED'] += 1


def new_res():
    keys = ['knob edits', 'knobs checked', 'knobs contested', 'knob DROP (uncontested)', 'knob DROP (other side on same effect)',
            'knob DIVERGED', 'knob LOST (contested)',
            'notes added', 'note DROP (uncontested)', 'note DROP (contested pattern+channel)', 'pattern DIVERGED',
            'clips added', 'clip DROP (uncontested)', 'clip DROP (contested track)', 'playlist DIVERGED', 'probe errors']
    return {k: 0 for k in keys}


if __name__ == '__main__':
    label = sys.argv[1] if len(sys.argv) > 1 else 'run'
    rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 12
    random.seed(1234)
    A, B = Side('A', mk.A), Side('B', mk.B)
    stop = threading.Event()
    for pid in (mk.A, mk.B): threading.Thread(target=sp.keepalive, args=(pid, stop), daemon=True).start()
    sp.mark('%s: setup (effects on inserts 1 and 2)' % label)
    while A.nchan() < 6:                              # FL's start project may have fewer channels
        with A.lock: A.p.call(A.v.ADDCHAN, 0xFFFFFFFFFFFFFFFF, 0, 1)
        time.sleep(2.5)
    A.add_fx(1); A.add_fx(2)
    time.sleep(10)
    report = {'label': label}
    for phase in ('separate', 'shared'):
        sp.mark('%s: phase %s' % (label, phase))
        t0 = clock()
        res = new_res()
        run_phase(A, B, phase, rounds, res)
        t1 = clock()
        res['log'] = log_counts(t0, t1, {mk.A, mk.B})
        report[phase] = res
    stop.set()
    sp.mark('%s: done' % label)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'stress_%s.json' % label)
    json.dump(report, open(out, 'w'), indent=1)
    print(json.dumps(report, indent=1))
