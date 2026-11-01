# The engine's per-FL-build table (k_flBuilds in engine/flim_engine.c) for the dev tools, plus the
# few addresses only the tools use. build(pid) = the row for an FL started by restart_test.ps1, from
# the engine log ("FL build 25.x.y.z: using its address table").
import os, re

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(HERE, '..', 'engine', 'flim_engine.c')
LOG = os.path.join(os.environ.get('TEMP', HERE), 'flim_engine.log')

# not used by the engine (mapped with sigscan.py like the engine's own)
TOOLS = {
    '25.2.3.5171': dict(FORMADDMARK=0xd4c810,      # editor form: add marker (form, pos, name, action, num, den)
                        PL_MARKERS=0xd50),         # playlist form: marker list being shown
    '25.1.6.4997': dict(FORMADDMARK=0xde9050, PL_MARKERS=0xd48),
    '25.2.5.5319': dict(FORMADDMARK=0xd523c0, PL_MARKERS=0xd5c),
}


def table():
    """{build: {NAME: value}} from k_flBuilds"""
    src = open(ENGINE, encoding='utf-8').read()
    body = src[src.index('static const FlBuild k_flBuilds[] = {'):]
    body = body[:body.index('\n};')]
    out = {}
    for row in re.findall(r'\{\s*//[^\n]*\n(.*?)\n    \},', body, re.S):
        build = re.search(r'\.build = L"([^"]+)"', row).group(1)
        vals = {k: int(v, 0) for k, v in re.findall(r'\.([A-Za-z_0-9]+)\s*=\s*(0x[0-9a-fA-F]+|\d+)', row)}
        vals.update(TOOLS.get(build, {}))
        out[build] = vals
    return out


def build_of(pid, log=LOG):
    t = open(log, encoding='utf-8', errors='replace').read()
    m = re.findall(r'\[%d\] FL build ([0-9.]+): using' % pid, t)
    if not m: raise LookupError('no "FL build" line for pid %d in %s' % (pid, log))
    return m[-1]


class Build(dict):
    """attribute access: V.REC, V.CH_GRID ..."""
    __getattr__ = dict.__getitem__


def build(pid):
    b = build_of(pid)
    return Build(table()[b], build=b)
