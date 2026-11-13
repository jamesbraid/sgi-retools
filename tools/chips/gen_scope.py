#!/usr/bin/env python3
"""Write the `scope` list of tools/config/inventory-config.json (old layout: scripts/) for this workspace.

The function table counts whole kernels and libraries, but only the code that drives or reports on a
system ASIC belongs to the work. A function is in scope when
  - its object is a chip driver or an attach, error or interrupt object of one (KEEP_OBJECTS), or
  - it holds a register access site of the census (devices/*/census/census-sites.tsv, chips/*/census/ on the old layout; a site in an
    address-named routine counts for the function that contains the address), or
  - it is a routine of the linked kernels, the object `kernel.o` or the debug monitor whose name carries a
    chip or its error and interrupt plumbing (NAME_PREFIX).
Every other object is excluded whole under one of four reasons. Run from the repository root after
`python3 retools/tools/inventory.py` has written evidence/inventory/, then run inventory.py again. `--check` fails when
the config is stale against the census, which is how a new census site cannot fall out of scope unnoticed.
`--slices PATH` writes the in-scope functions of functions.tsv in four slices, one per build (the
standalone programs go with IP32).
"""
import collections
import csv
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from _workspace import find_workspace  # noqa: E402
from _layout import Layout  # noqa: E402
REPO = find_workspace()
LAYOUT = Layout(REPO)
CFG = os.path.join(REPO, LAYOUT.inventory_config)
FUNCTIONS = os.path.join(REPO, LAYOUT.functions_table)

KEEP_OBJECTS = '''pcibr.o pciio.o pciio_ppb.o pciiox.o pic.o xbridge.o xbow.o xswitch.o xtalk.o xconn.o xbmon.o hubspc.o
ioc3.o ioc3ei.o ioc3_pckm.o ioc4.o ioc4_ei.o ioc4_pckm.o if_ef.o l1.o l1_command.o nic.o eeprom.o partition.o
io6.o sn0drv.o heart.o mace.o a3_dd.o rad_dd.o ecplp.o if_ecf.o if_me.o mhpckm.o mvp.o pcimh.o
sduart.a(sio_ioc3.o) sduart.a(sio_ioc4.o) sduart.a(sio_l1.o)'''.split()

NAME_PREFIX = (r'(?:early_|hub|huberror|md_|mdir_|ni_|router_|xbow|xbwidget|xswitch|xtalk|xwidget|xconn|pcibr|pciio|bridge|'
               r'heart|ioc3|ioc4|tiocp|pic_|crime|mace|gbe|save_(?:hub|bridge|xbow|router)|show_(?:hub|bridge|xbow)|'
               r'kl_|klerror|klhwg|sn0_|sn1_|intr_|intrgroup_|nmi|bte|crb|nic_|l1_|ii_)')

# (reason, regex over the object's base name without the .o; archives use the archive name for members)
CLASSES = [
    ('file-system, volume-manager and disk-quota objects: block and file code, excluded by role from object names and imports, not by a scan',
     r'^(efs|xfs|xlv|xvm|nfs|snfs|nfs3|cachefs|lofs|udf|umfs|dmi|dms|namefs|pipefs|fifofs|specfs|hwgfs|proc|autofs|'
     r'acl|ds|quotas|fsctl|sgi|dksc|xfsrt|xfsdmapi|xfsquotas|cpr|fd|pgrpidbg|procidbg|spec_idbg)'),
    ('network protocol, RPC and STREAMS objects, and network-interface drivers other than the IOC3 and IOC4 '
     'Ethernet objects, excluded by role from object names and imports, not by a scan',
     r'^(bsd|ipv6|stp|llc2|fddi|snif|oncrpc|oncrpcidbg|rpcsec|sockmod|tpi|ti|uds|if_|ip_|ppp|stream|sad|log|clone|'
     r'connld|pipemod|ptem|stty|timod|tirdwr|ticlts|ticots|ticotsord|ipfilter|irouter|tpisocket|tpitcp|tpiudp|'
     r'tpirawip|tpiicmp|imon|sat|cl|cn|ptc|msg|sem|shmiq|stridbg|spi|tsv|lockd|imp)'),
    ('process, memory, scheduler, synchronisation, timer and debugger core: machine-independent kernel code, '
     'excluded by role from object names and imports, not by a scan',
     r'^(os|disp|disp_idbg|ksync|kmem|numa|numa_idbg|noncell|hardlocks|nolocks|dhardlocks|jlimits|xtimer|capability|'
     r'suser|rand|crypto|compression|eag|kitchen_sync|klog|klidbg|mem|mem_alloc|sharena|usema|usync|psema|oplock|'
     r'prf|prio_alloc|ipc|zero|ude|asidbg|sessionidbg|cdl|devpoll|qcntl|uncintf|kdsp|io|graph|graphidbg|failover|'
     r'mloadidbg|idbg|clshm|xpmem|xpc|uli|smfd|ts|tsd|ls|lsidbg|idev|dial|dialbox|dmiidbg|grio|grio2|grio2idbg|'
     r'grioidbg|fru|jtagio|vmeuli|elsc|i2c|sio_i2c)'),
    ('device drivers (SCSI, Fibre Channel, USB, VGA, audio, tape, serial lines, input devices, VME, graphics, '
     'IEEE 1394) and the standalone loader that do not drive a system ASIC, excluded by role from object names and '
     'imports, not by a scan',
     r'^(scsi|scsiha|adp78|adphim|adpidbg|fcadp|fcidbg|qlfc|qlfc_idbg|ql|qlidbg|usb|usb_comp|usb_pckm|usb_tablet|'
     r'usbaudio_dd|usbidbg|vga|sbp2|sbp2idbg|sndrv|nsmidi|tpsc|tpu|tpuidbg|tpusim|tpscutil|tsutil|universe|vme|'
     r'vmeio|vmidbg|vme_idbg|xiovme|usrvme|usrbus|usrdma|usrpci|sball|fire|fireidbg|rad1pci|emu_dd|mad_dd|fglrx|'
     r'calcomp|hitachi|wacom|magellan|tablet|kbd|keyboard|mouse|tportpckbd|pciba|cserialio|tserialio|userialio|'
     r'serialio|gentty|isdn|alp|bpqueue|is1|menet|mio|htport|ptrmap|xioba|giobr|gioio|sflash|csr|dsglue|sduart|'
     r'ide|ide_idbg|ec|ecpplp|sash64)'),
]

# Routines of a linked kernel whose names carry no chip name and that the census has no site for, but that the
# inventory's own scan finds reaching a register window or a token once their address is recovered. A rule
# cannot exclude such a routine, so they stay in scope. Keyed by the base name of the binary.
SCAN_FOUND = {'kernel.o': {'add_vice', 'ecc_fixmem', 'err_save_regs'}}


def tsv(path):
    with open(path, newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f, delimiter='\t'))


def base(label):
    return label.split('boot/', 1)[1] if 'boot/' in label else label


def is_big(label):
    return label.endswith('/unix') or base(label) in ('kernel.o', 'sbin/stand/symmon.IP32')


def census_functions(funcs, spans, labels):
    """{binary label: set of function names} for every census access site."""
    image_path = {}
    for f in glob.glob(os.path.join(REPO, 'tools', 'configs', '*.json')):
        for i in json.load(open(f))['images']:
            image_path[i['label']] = i['path']
    sites = collections.defaultdict(set)
    for f in sorted(glob.glob(os.path.join(REPO, 'devices', '*', 'census', 'census-sites.tsv')) +
                    glob.glob(os.path.join(REPO, 'chips', '*', 'census', 'census-sites.tsv'))):
        for r in tsv(f):
            sites[r['image']].add(r['function'])
    out = collections.defaultdict(set)
    for img, names in sites.items():
        p = image_path[img][5:]
        m = re.match(r'(IP\d+)/usr/cpu/sysgen/(IP\d+boot)/(\w+\.a)_members/(.+)$', p)
        if m:
            cands = ['%s/usr/cpu/sysgen/%s/%s(%s)' % (m[1], m[2], m[3], m[4])]
        else:
            m = re.match(r'(IP\d+)/members/(.+)$', p)
            cands = [l for l in labels if l.startswith(m[1] + '/') and l.endswith('(' + m[2] + ')')] if m else [p]
        for lab in (c for c in cands if c in funcs):
            for n in names:
                if n in funcs[lab]:
                    out[lab].add(n)
                    continue
                m = re.fullmatch(r'sub_([0-9a-f]+)', n)
                if m:
                    a = int(m[1], 16)
                    out[lab].update(nm for (b, z, nm) in spans[lab] if b <= a < b + z)
    return out


def globs(chosen, labels, spare):
    """Short globs for the chosen labels: one per archive of a build when every member of the archive is chosen
    (so a new member of it would be caught by the stale check, not silently left out), else the label itself."""
    chosen, out = set(chosen), []
    members = collections.defaultdict(list)
    for l in labels:
        m = re.match(r'^(.*\.a)\(.*\)$', l)
        if m:
            members[m[1]].append(l)
    done = set()
    for l in sorted(chosen):
        m = re.match(r'^(.*\.a)\(.*\)$', l)
        if m and not any(x in spare or x not in chosen for x in members[m[1]]):
            if m[1] not in done:
                done.add(m[1])
                out.append(m[1] + '(*)')
        else:
            out.append(l)
    return out


def build():
    inv = os.path.join(REPO, LAYOUT.inventory_dir)
    funcs, spans = collections.defaultdict(set), collections.defaultdict(list)
    for r in tsv(os.path.join(inv, 'functions.tsv')):
        funcs[r['binary']].add(r['name'])
        if r['size'] and int(r['address'], 16):
            spans[r['binary']].append((int(r['address'], 16), int(r['size']), r['name']))
    labels = sorted(funcs)
    cen = census_functions(funcs, spans, labels)
    prefix = re.compile(NAME_PREFIX)
    rules, keep_all = [], set(KEEP_OBJECTS)
    whole = lambda l: base(l) in keep_all or base(l).startswith('crime.a(')
    groups = collections.defaultdict(list)
    partial = []
    for l in labels:
        if whole(l):
            continue
        if is_big(l):
            partial.append((l, cen.get(l, set()) | {n for n in funcs[l] if prefix.match(n)} |
                            (SCAN_FOUND.get(base(l), set()) & funcs[l]),
                            'routines of a linked kernel or debug monitor whose names carry no chip or chip-error '
                            'name and hold no census access site: machine-independent kernel code'))
        elif l in cen:
            partial.append((l, cen[l], 'routines of an object that is not a chip driver and hold no census access '
                            'site: the object is in scope only for the routines that touch a chip'))
        else:
            stem = re.sub(r'\.o$', '', (re.match(r'^(.*?)\.a\(', base(l)) or [None, os.path.basename(base(l))])[1])
            for i, (_, rx) in enumerate(CLASSES):
                if re.match(rx, stem):
                    groups[i].append(l)
                    break
            else:
                sys.exit('gen_scope: no exclusion class for %s' % l)
    spare = {l for l, _, _ in partial} | {l for l in labels if whole(l)}
    for i, (reason, _) in enumerate(CLASSES):
        if groups[i]:
            rules.append({'binaries': globs(groups[i], labels, spare), 'reason': reason, 'patterns': ['.+']})
    for l, keep, reason in partial:
        pat = '(?!(?:%s)$).+' % '|'.join(re.escape(n) for n in sorted(keep)) if keep else '.+'
        rules.append({'binaries': [l], 'reason': reason, 'patterns': [pat]})
    return rules, funcs, cen, whole


def slices(path):
    """The rows functions.tsv marks `in`, grouped by binary."""
    keep = collections.defaultdict(list)
    for r in tsv(FUNCTIONS):
        if r['scope'] == 'in':
            keep[r['binary']].append(r['name'])
    rows = [(b, sorted(ns)) for b, ns in sorted(keep.items())]

    def build(b):
        m = re.match(r'(IP\d+)/', b)
        return m[1] if m else 'standalone'
    by = collections.defaultdict(list)
    for b, ns in rows:
        by[build(b)].append((b, ns))
    parts = [('slice 1: IP27 build', by['IP27']), ('slice 2: IP30 build', by['IP30']),
             ('slice 3: IP32 build and standalone', by['IP32'] + by['standalone']), ('slice 4: IP35 build', by['IP35'])]
    with open(path, 'w', encoding='utf-8') as f:
        f.write('# In-scope function slices\n\nGenerated by `retools/tools/chips/gen_scope.py --slices`. One line per binary: '
                'the binary, the count, then the function names.\n')
        for title, items in parts:
            f.write('\n## %s (%d functions in %d binaries)\n\n' % (title, sum(len(n) for _, n in items), len(items)))
            for b, ns in items:
                f.write('- `%s` (%d): %s\n' % (b, len(ns), ' '.join(ns)))


def main():
    rules, funcs, cen, whole = build()
    cfg = json.load(open(CFG))
    if '--check' in sys.argv:
        if cfg.get('scope') != rules:
            sys.exit('gen_scope: the scope list in %s is stale; run retools/tools/chips/gen_scope.py' % CFG)
        scoped = {(r['binary'], r['name']): r['scope'] for r in tsv(FUNCTIONS)}
        bad = sorted((b, n) for b, ns in cen.items() for n in ns if scoped.get((b, n)) != 'in')
        if bad:
            sys.exit('gen_scope: census access-site routines out of scope or missing from functions.tsv: %s' % bad[:10])
        return
    if '--slices' in sys.argv:
        slices(sys.argv[sys.argv.index('--slices') + 1])
        return
    cfg['scope'] = rules
    with open(CFG, 'w', encoding='utf-8') as f:
        f.write(json.dumps(cfg, indent=1))
    print('%d scope rules' % len(rules))


if __name__ == '__main__':
    main()
