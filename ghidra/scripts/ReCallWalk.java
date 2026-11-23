// One record per call site, from the instructions and their raw p-code, not from the decompiler. A plain
// helper class: scripts call ReCallWalk.walk.
//   kind  direct      the target is in the instruction
//         constant    the register holds a constant at the site; source is the image word it was read from, if any
//         table       the register was loaded from a table in the image at a computed index; source is its first entry
//         unresolved  none of those
// tail is set for a jump to another function's entry.
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public final class ReCallWalk {
    public static final class Call {
        public final Address site;
        public final Address function;
        public final Address target;   // null when not resolved to one address
        public final String kind;
        public final Address source;   // null when none
        public final boolean tail;

        Call(Address site, Address function, Address target, String kind, Address source, boolean tail) {
            this.site = site; this.function = function; this.target = target; this.kind = kind;
            this.source = source; this.tail = tail;
        }
    }

    private ReCallWalk() {}

    public static List<Call> walk(Program program, Function f) {
        List<Call> out = new ArrayList<>();
        ReBlockEval eval = new ReBlockEval(program);
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        eval.walk(f, new ReBlockEval.Listener() {
            @Override
            public void call(Address site, Address direct, ReBlockEval.Val t) {
                if (direct != null) {
                    out.add(new Call(site, f.getEntryPoint(), direct, "direct", null, false));
                } else if (t.known) {
                    out.add(new Call(site, f.getEntryPoint(), space.getAddress(t.value), "constant",
                        t.source >= 0 ? space.getAddress(t.source) : null, false));
                } else if (t.indexed && t.source >= 0) {
                    out.add(new Call(site, f.getEntryPoint(), null, "table", space.getAddress(t.source), false));
                } else {
                    out.add(new Call(site, f.getEntryPoint(), null, "unresolved", null, false));
                }
            }

            @Override
            public void tail(Address site, Address target) {
                out.add(new Call(site, f.getEntryPoint(), target, "direct", null, true));
            }
        });
        return out;
    }

    /** Every function's calls, sorted by site and then target. */
    public static List<Call> walk(Program program, TaskMonitor monitor) throws Exception {
        List<Call> all = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            if (f.isExternal() || f.isThunk()) continue;
            all.addAll(walk(program, f));
        }
        all.sort(Comparator.comparing((Call c) -> c.site).thenComparing(c -> c.target == null ? 1 : 0)
            .thenComparing(c -> c.target == null ? c.site : c.target));
        return all;
    }
}
