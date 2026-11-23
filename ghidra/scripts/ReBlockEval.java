// Block-local constant evaluation over a function's raw p-code, shared by ReCallWalk and ReAccessWalk. It
// follows constants through register copies, adds, shifts and ors, and through loads from read-only
// memory, until the block ends: a branch target, a branch or a call. It never runs the decompiler and
// uses no timeout, so what it finds does not depend on a budget or on how busy the host is.
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public final class ReBlockEval {
    /** A value: known, or a known constant plus something unknown ("partial"), with where it was read from. */
    public static final class Val {
        public final boolean known;
        public final boolean partial;
        public final long value;    // the value if known, the constant addend if partial
        public final long source;   // address of the image word it was read from, or of the table it was indexed in; -1 none
        public final boolean indexed;
        public final Set<Long> loads;  // sites of the loads this value depends on
        public boolean modified;       // some operation other than a copy or resize was applied to it

        Val(boolean known, boolean partial, long value, long source, boolean indexed, Set<Long> loads) {
            this.known = known; this.partial = partial; this.value = value; this.source = source;
            this.indexed = indexed; this.loads = loads;
        }
    }

    public interface Listener {
        /** A LOAD: its address, width and site. */
        default void load(Address site, Val address, int size) {}
        /** A STORE: the address, value, width and site, and the id of the basic block it is in. */
        default void store(Address site, Val address, Val value, int size, int block) {}
        /** CALL or CALLIND: target is null for a direct call, whose address is in direct. */
        default void call(Address site, Address direct, Val target) {}
        /** A BRANCH out of the function to the entry of another one. */
        default void tail(Address site, Address target) {}
    }

    private static final Set<Long> NONE = Collections.emptySet();
    private static final Val UNKNOWN = new Val(false, false, 0, -1, false, NONE);

    private final Program program;
    private final Memory memory;
    private final boolean big;
    // What is known of each register or temporary written so far in the block. Entries never overlap.
    private static final class Slot {
        final String space;
        final long offset;
        final int size;
        final Val val;

        Slot(String space, long offset, int size, Val val) {
            this.space = space; this.offset = offset; this.size = size; this.val = val;
        }
    }

    private final Map<String, Slot> state = new HashMap<>();
    private final Map<Long, Integer> loadBlock = new HashMap<>();
    private Set<Address> targets = new HashSet<>();
    private int block;

    public ReBlockEval(Program program) {
        this.program = program;
        this.memory = program.getMemory();
        this.big = program.getLanguage().isBigEndian();
    }

    public int block() {
        return block;
    }

    /** The basic block a load site was seen in, for pairing a store with it. */
    public int blockOfLoad(long site) {
        Integer b = loadBlock.get(site);
        return b == null ? -1 : b;
    }

    public void walk(Function f, Listener l) {
        state.clear();
        loadBlock.clear();
        block = 0;
        targets = new HashSet<>();
        InstructionIterator scan = program.getListing().getInstructions(f.getBody(), true);
        while (scan.hasNext()) {
            Instruction in = scan.next();
            if (in.getFlowType().isCall()) continue;
            for (Address a : in.getFlows()) if (f.getBody().contains(a)) targets.add(a);
        }
        InstructionIterator it = program.getListing().getInstructions(f.getBody(), true);
        boolean first = true;
        while (it.hasNext()) {
            Instruction in = it.next();
            if (in.isInDelaySlot()) continue;
            if (!first && targets.contains(in.getAddress())) {
                state.clear();
                block++;
            }
            first = false;
            step(f, in, l);
            FlowType ft = in.getFlowType();
            if (ft.isCall() || ft.isTerminal() || (ft.isJump() && !ft.isConditional())) {
                state.clear();
                block++;
            } else if (ft.isJump()) {
                block++;
            }
        }
    }

    private static long mask(long v, int size) {
        return size >= 8 ? v : v & ((1L << (8 * size)) - 1);
    }

    private static long sext(long v, int size) {
        return size >= 8 ? v : (v << (64 - 8 * size)) >> (64 - 8 * size);
    }

    private String key(Varnode v) {
        return v.getAddress().getAddressSpace().getName() + ":" + v.getOffset() + ":" + v.getSize();
    }

    private Val read(Varnode v) {
        if (v.isConstant()) return new Val(true, false, mask(v.getOffset(), v.getSize()), -1, false, NONE);
        if (v.isRegister()) {
            Register r = program.getRegister(v.getAddress(), v.getSize());
            if (r != null && (r.getName().equals("zero") || r.getName().equals("r0")))
                return new Val(true, false, 0, -1, false, NONE);
        }
        Slot exact = state.get(key(v));
        if (exact != null) return exact.val;
        String space = v.getAddress().getAddressSpace().getName();
        long o = v.getOffset();
        for (Slot s : state.values()) {
            if (!s.space.equals(space) || s.offset > o || s.offset + s.size < o + v.getSize()) continue;
            // A part of a wider value: take its bytes, counting from the most significant end when big-endian.
            Val part;
            if (!s.val.known && !s.val.partial) {
                part = new Val(false, false, 0, -1, false, s.val.loads);
            } else {
                long shift = big ? 8L * (s.offset + s.size - (o + v.getSize())) : 8L * (o - s.offset);
                part = new Val(s.val.known, s.val.partial, mask(shift >= 64 ? 0 : s.val.value >>> shift, v.getSize()),
                    s.val.source, s.val.indexed, s.val.loads);
            }
            part.modified = s.val.modified;
            return part;
        }
        return UNKNOWN;
    }

    private void write(Varnode out, Val v, boolean guarded) {
        if (out == null) return;
        String space = out.getAddress().getAddressSpace().getName();
        long o = out.getOffset();
        state.values().removeIf(s -> s.space.equals(space) && s.offset < o + out.getSize() && o < s.offset + s.size);
        Val kept = guarded ? new Val(false, false, 0, -1, false, v.loads) : v;
        state.put(key(out), new Slot(space, o, out.getSize(), kept));
    }

    private static Set<Long> union(Set<Long> a, Set<Long> b) {
        if (a.isEmpty()) return b;
        if (b.isEmpty()) return a;
        Set<Long> u = new HashSet<>(a);
        u.addAll(b);
        return u;
    }

    private Val fold(PcodeOp op, int size, Val a, Val b) {
        Val r = foldOp(op, size, a, b);
        int c = op.getOpcode();
        r.modified = (c == PcodeOp.COPY || c == PcodeOp.INT_ZEXT || c == PcodeOp.INT_SEXT || c == PcodeOp.SUBPIECE)
            ? a.modified : true;
        return r;
    }

    private Val foldOp(PcodeOp op, int size, Val a, Val b) {
        Set<Long> loads = union(a.loads, b.loads);
        long src = a.source >= 0 ? a.source : b.source;
        boolean idx = a.indexed || b.indexed;
        switch (op.getOpcode()) {
            case PcodeOp.COPY: return new Val(a.known, a.partial, mask(a.value, size), a.source, a.indexed, a.loads);
            case PcodeOp.INT_ZEXT:
                return new Val(a.known, a.partial, a.value, a.source, a.indexed, a.loads);
            case PcodeOp.INT_SEXT:
                return new Val(a.known, a.partial, a.known || a.partial ? mask(sext(a.value, op.getInput(0).getSize()), size) : 0,
                    a.source, a.indexed, a.loads);
            case PcodeOp.SUBPIECE: {
                if (!a.known) return new Val(false, false, 0, -1, false, a.loads);
                long shift = 8 * op.getInput(1).getOffset();
                return new Val(true, false, mask(shift >= 64 ? 0 : a.value >>> shift, size), a.source, false, a.loads);
            }
            case PcodeOp.INT_ADD: case PcodeOp.INT_SUB: {
                boolean add = op.getOpcode() == PcodeOp.INT_ADD;
                if (a.known && b.known) return new Val(true, false, mask(add ? a.value + b.value : a.value - b.value, size), src, false, loads);
                if (add && a.known && !b.known && !b.partial) return new Val(false, true, a.value, src, true, loads);
                if (add && b.known && !a.known && !a.partial) return new Val(false, true, b.value, src, true, loads);
                if (add && a.known && b.partial) return new Val(false, true, mask(a.value + b.value, size), b.source, true, loads);
                if (add && b.known && a.partial) return new Val(false, true, mask(a.value + b.value, size), a.source, true, loads);
                return new Val(false, false, 0, -1, false, loads);
            }
            case PcodeOp.INT_2COMP:
                return a.known ? new Val(true, false, mask(-a.value, size), a.source, false, a.loads)
                    : new Val(false, false, 0, -1, false, a.loads);
            case PcodeOp.INT_OR: case PcodeOp.INT_AND: case PcodeOp.INT_XOR: case PcodeOp.INT_LEFT: case PcodeOp.INT_RIGHT:
            case PcodeOp.INT_SRIGHT: case PcodeOp.INT_MULT: {
                if (!(a.known && b.known)) {
                    // A mask or shift of a table load keeps what it was loaded from.
                    Val u = a.known ? b : a;
                    boolean keep = (a.known || b.known) && u.indexed;
                    return new Val(false, false, 0, keep ? u.source : -1, keep, loads);
                }
                long r;
                switch (op.getOpcode()) {
                    case PcodeOp.INT_OR: r = a.value | b.value; break;
                    case PcodeOp.INT_AND: r = a.value & b.value; break;
                    case PcodeOp.INT_XOR: r = a.value ^ b.value; break;
                    case PcodeOp.INT_LEFT: r = b.value >= 64 ? 0 : a.value << b.value; break;
                    case PcodeOp.INT_RIGHT: r = b.value >= 64 ? 0 : a.value >>> b.value; break;
                    case PcodeOp.INT_SRIGHT: r = sext(a.value, op.getInput(0).getSize()) >> Math.min(63, b.value); break;
                    default: r = a.value * b.value;
                }
                return new Val(true, false, mask(r, size), src, false, loads);
            }
            default:
                return new Val(false, false, 0, -1, false, loads);
        }
    }

    private boolean readOnly(Address a) {
        MemoryBlock b = memory.getBlock(a);
        return b != null && b.isInitialized() && !b.isWrite();
    }

    private long word(Address a, int size) throws Exception {
        byte[] buf = new byte[size];
        memory.getBytes(a, buf);
        long v = 0;
        for (int i = 0; i < size; i++) {
            int bt = buf[big ? i : size - 1 - i] & 0xff;
            v = (v << 8) | bt;
        }
        return v;
    }

    private Address addr(AddressSpace space, long v) {
        try {
            return space.getAddress(v);
        } catch (Exception e) {
            return null;
        }
    }

    /** True when the address is inside a block the program holds, so a device access is not meant. */
    public boolean inImage(long v, AddressSpace space) {
        Address a = addr(space, v);
        return a != null && memory.contains(a);
    }

    private AddressSpace space(PcodeOp op) {
        return program.getAddressFactory().getAddressSpace((int) op.getInput(0).getOffset());
    }

    // A constant address wraps to the width of the space it names: a sign-extended 32-bit pointer
    // loaded into a 64-bit register addresses a 32-bit space.
    private static Val address(Val a, AddressSpace space) {
        long max = space.getMaxAddress().getOffset();
        if (!a.known && !a.partial) return a;
        return new Val(a.known, a.partial, a.value & max, a.source, a.indexed, a.loads);
    }

    private void step(Function f, Instruction in, Listener l) {
        boolean guarded = false;
        for (PcodeOp op : in.getPcode(true)) {
            Address site = op.getSeqnum().getTarget();
            int opc = op.getOpcode();
            Varnode out = op.getOutput();
            // Whatever follows a conditional branch inside one instruction runs only on one path: a predicated
            // IA-64 instruction, a MIPS branch-likely delay slot.
            if (opc == PcodeOp.CBRANCH) { guarded = true; continue; }
            if (opc == PcodeOp.BRANCH && op.getInput(0).isConstant()) continue;
            if (opc == PcodeOp.BRANCH) {
                Address t = op.getInput(0).getAddress();
                Function g = program.getFunctionManager().getFunctionAt(t);
                if (g != null && !g.equals(f)) l.tail(site, t);
                continue;
            }
            if (opc == PcodeOp.CALL) {
                l.call(site, op.getInput(0).getAddress(), null);
                continue;
            }
            if (opc == PcodeOp.CALLIND) {
                l.call(site, null, read(op.getInput(0)));
                continue;
            }
            if (opc == PcodeOp.STORE) {
                Val a = address(read(op.getInput(1)), space(op));
                Val v = read(op.getInput(2));
                l.store(site, a, v, op.getInput(2).getSize(), block);
                continue;
            }
            if (opc == PcodeOp.LOAD) {
                AddressSpace space = space(op);
                Val a = address(read(op.getInput(1)), space);
                int size = out.getSize();
                l.load(site, a, size);
                long s = site.getOffset();
                loadBlock.put(s, block);
                Set<Long> loads = union(a.loads, Collections.singleton(s));
                Val v;
                Address at = a.known ? addr(space, a.value) : null;
                try {
                    if (at != null && readOnly(at) && memory.contains(at.add(size - 1))) {
                        v = new Val(true, false, word(at, size), a.value, false, loads);
                    } else if (a.partial && addr(space, a.value) != null && readOnly(addr(space, a.value))) {
                        v = new Val(false, false, 0, a.value, true, loads);
                    } else {
                        v = new Val(false, false, 0, -1, false, loads);
                    }
                } catch (Exception e) {
                    v = new Val(false, false, 0, -1, false, loads);
                }
                write(out, v, guarded);
                continue;
            }
            if (out == null) continue;
            Val a = op.getNumInputs() > 0 ? read(op.getInput(0)) : UNKNOWN;
            Val b = op.getNumInputs() > 1 ? read(op.getInput(1)) : UNKNOWN;
            write(out, fold(op, out.getSize(), a, b), guarded);
        }
    }
}
