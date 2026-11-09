exec(open("su1.py").read().split("\nif __name__")[0])
import csv
syms={}
for row in csv.reader(open('../../docs/inventory/functions.tsv'),delimiter='\t'):
    if row and row[0].endswith('crm.so') and row[4].startswith('0x'): syms[int(row[4],16)]=row[6]
SITES={0x4c2590:[0x4c2854],0x4c4d20:[0x4c4db8,0x4c4ea4],0x4c5c10:[0x4c5ca4,0x4c5db4,0x4c61a4],0x4871a0:[0x4872fc],0x482f00:[0x483060],0x4e6f20:[0x4e6fac],0x4e7e20:[0x4e7ea0],0x4e4a30:[]}
def probe(fn,bpp,rect):
    rng=random.Random(5); seen=collections.OrderedDict()
    import types
    for it in range(30):
        # reuse trial_u or trial machinery by monkeypatching CPU.call to install hooks
        pass
orig=CPU.call
def call(s,fn,args=(),**kw):
    for site in SITES.get(fn,[]):
        s.hooks[site]=lambda st,site=site: CALLS.setdefault(site,set()).add(st.r[25])
    return orig(s,fn,args,**kw)
CPU.call=call
for fn,bpp,rect,mod,op in [(0x4c5c10,8,False,'u',0),(0x4871a0,16,False,'u',0),(0x482f00,32,False,'u',0),(0x4e7e20,8,True,'u',0)]:
    CALLS={}; rng=random.Random(5)
    for it in range(25): trial_u(fn,bpp,rng,rect)
    print(hex(fn),{hex(k):[syms.get(a,hex(a)) for a in v] for k,v in CALLS.items()})
exec(open("sp3.py").read().split("\nif __name__")[0].split("\n",1)[1]) if False else None
