// One record per load or store whose address resolves to a constant outside the program's own memory (a
// device), from the instructions and their raw p-code, not from the decompiler. A plain helper class:
// scripts call ReAccessWalk.walk.
//   op          load, store, or rmw: a load, operations on its value, and a store of it to the same address
//               and width in one basic block, which is one record at the store, with loadSite
//   addressing  absolute     the address is built from constants in the function
//               base+offset  the base was loaded from a word of the image (base) and a displacement was added
//   value       on a store or rmw, what was stored: 0xHEX for a constant, load@0xSITE[,load@0xSITE] for a value that came
//               from loads in the same block, ? otherwise
//   uses        on a load or rmw, the operations in the same block that meet the loaded value with a constant, in
//               order and without repeats (at most MAX_USES), such as "and 0xff", "eq 0x3", "sub 0x7b2", "ltu 0x10"
//               (the loaded value is on the left: "ltu 0x10" is value < 0x10). Operations on a value derived from
//               the load count, so a chain "and 0xff" then "eq 0x3" lists both. A word read through a loaded pointer is
//               a new load, not a use of the pointer, and an addressing mode's own add is not an add. They are the walk's
//               own observations, as established as the address.
// A modify that crosses a branch is a load and a store. physical comes from RePhysical. site is the
// instruction's address, except that an access in a branch delay slot is at the branch: Ghidra gives the slot's
// p-code to it.
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class ReAccessWalk {
    public static final class Access {
        public final Address site;
        public final Address function;
        public final long address;
        public final long physical;
        public final int width;
        public final String op;
        public final String addressing;
        public final Address base;      // null unless base+offset
        public final Address loadSite;  // null unless rmw
        public final String value;      // "" on a load
        public final List<String> uses; // empty on a plain store

        Access(Address site, Address function, long address, long physical, int width, String op,
               String addressing, Address base, Address loadSite, String value, List<String> uses) {
            this.site = site; this.function = function; this.address = address; this.physical = physical;
            this.width = width; this.op = op; this.addressing = addressing; this.base = base; this.loadSite = loadSite;
            this.value = value; this.uses = uses;
        }
    }

    public static final int MAX_USES = 8;

    private ReAccessWalk() {}

    private static String value(ReBlockEval.Val v) {
        if (v.known) return "0x" + Long.toHexString(v.value);
        List<Long> sites = new ArrayList<>(v.loads);
        if (sites.isEmpty()) return "?";
        java.util.Collections.sort(sites);
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < sites.size() && i < 4; i++) b.append(i > 0 ? "," : "").append("load@0x").append(Long.toHexString(sites.get(i)));
        return b.toString();
    }

    public static List<Access> walk(Program program, Function f) {
        List<Access> out = new ArrayList<>();
        Map<Long, Access> loads = new HashMap<>();
        Map<Long, Access> byLoad = new HashMap<>();  // a load site to the record that now stands for it
        ReBlockEval eval = new ReBlockEval(program);
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        eval.walk(f, new ReBlockEval.Listener() {
            private String how(ReBlockEval.Val a) {
                return a.source >= 0 ? "base+offset" : "absolute";
            }

            private Address base(ReBlockEval.Val a) {
                return a.source >= 0 ? space.getAddress(a.source) : null;
            }

            @Override
            public void load(Address site, ReBlockEval.Val a, int size) {
                if (!a.known || eval.inImage(a.value, space)) return;
                Access x = new Access(site, f.getEntryPoint(), a.value,
                    RePhysical.toPhysical(program.getLanguage().getProcessor(), a.value), size, "load", how(a), base(a), null,
                    "", new ArrayList<>());
                out.add(x);
                loads.put(site.getOffset(), x);
                byLoad.put(site.getOffset(), x);
            }

            @Override
            public void use(Address site, String op, long constant, java.util.Set<Long> from) {
                String u = op + " 0x" + Long.toHexString(constant);
                for (long l : from) {
                    Access x = byLoad.get(l);
                    if (x != null && x.uses.size() < MAX_USES && !x.uses.contains(u)) x.uses.add(u);
                }
            }

            @Override
            public void store(Address site, ReBlockEval.Val a, ReBlockEval.Val v, int size, int block) {
                if (!a.known || eval.inImage(a.value, space)) return;
                long phys = RePhysical.toPhysical(program.getLanguage().getProcessor(), a.value);
                // The nearest earlier load of the same address and width in this block whose value was changed.
                Access pair = null;
                if (v.modified) {
                    for (long l : v.loads) {
                        Access ld = loads.get(l);
                        if (ld != null && ld.address == a.value && ld.width == size && eval.blockOfLoad(l) == block
                            && (pair == null || l > pair.site.getOffset())) pair = ld;
                    }
                }
                if (pair != null) {
                    out.remove(pair);
                    loads.remove(pair.site.getOffset());
                    Access m = new Access(site, f.getEntryPoint(), a.value, phys, size, "rmw", how(a), base(a), pair.site,
                        value(v), pair.uses);
                    byLoad.put(pair.site.getOffset(), m);
                    out.add(m);
                    return;
                }
                out.add(new Access(site, f.getEntryPoint(), a.value, phys, size, "store", how(a), base(a), null, value(v),
                    new ArrayList<>()));
            }
        });
        return out;
    }

    /** Every function's accesses, sorted by site. */
    public static List<Access> walk(Program program, TaskMonitor monitor) throws Exception {
        List<Access> all = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            if (f.isExternal() || f.isThunk()) continue;
            all.addAll(walk(program, f));
        }
        all.sort(Comparator.comparing((Access a) -> a.site));
        return all;
    }
}
