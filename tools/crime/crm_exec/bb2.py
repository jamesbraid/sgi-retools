exec(open("bb1.py").read().split("\nif __name__")[0])
rng=random.Random(3)
for it in range(400):
    st=rng.getstate(); r=one('General',8,rng)
    if r and r[0]=='halt': print(r); rng.setstate(st); break
rng2=random.Random(3)
# Or/Xor with a partial plane mask: is it ignored?
src=open("bb1.py").read()
