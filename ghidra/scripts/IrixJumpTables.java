// Recover the jump tables of IRIX MIPS switch statements that Ghidra leaves
// as "indirect jump treated as call", and attach them to the function.
//
// Run it as a post-script, after IrixGp.java (pre-script) and auto-analysis:
//
//   analyzeHeadless DIR proj -import FILE -preScript IrixGp.java \
//       -postScript IrixJumpTables.java -postScript YOURS.java ...
//
// The compiler's dispatch is: bound check (sltiu idx,N / beqz), table base
// built from a GOT or small-data slot plus a low half, base + 4*idx (8*idx on
// 64-bit), a load of the entry, jr. Ghidra's emulation gives up because the
// base comes from a GOT slot. This script walks back from each jr over the
// straight-line instructions with a tiny constant evaluator (lui, addiu,
// ori, move, addu, gp-relative loads read from the loaded image), finds the
// table base and the case count from the bound check, reads the entries,
// adds a computed-jump reference from the jr to each, registers the table
// with the decompiler as a jump-table override (the same call Ghidra's own
// SwitchOverride script makes) and re-flows the function body.
//
// Ghidra's ELF loader also applies the shared objects' R_MIPS_REL32 relocations
// to table entries that already hold final addresses, so the table in memory
// holds garbage (a constant added to every entry). For a shared object this
// script therefore reads the entries from the file's original bytes. A
// relocatable kernel object has no final addresses in the file; its entries
// come from the relocated memory image.
//
// Limits: entries are absolute addresses (the shape both the shared objects
// and the kernel objects use; a gp-relative entry table is not handled and is
// reported); the bound must be a sltiu in the 24 instructions before the jr;
// tables reached through a register the evaluator cannot follow are reported
// and left alone. Prints "IrixJumpTables:" lines saying what it did.
// @category RE
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.database.mem.FileBytes;
import java.math.BigInteger;
import java.util.*;

public class IrixJumpTables extends GhidraScript {
    private Memory mem;
    private long gpValue;
    private boolean haveGp;
    private boolean relocatable;

    @Override
    public void run() throws Exception {
        mem = currentProgram.getMemory();
        relocatable = mem.getBlock(".got") == null;
        Register gp = currentProgram.getRegister("gp");
        int fixed = 0, skipped = 0;
        List<Function> todo = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) todo.add(f);
        for (Function f : todo) {
            haveGp = false;
            RegisterValue rv = currentProgram.getProgramContext().getRegisterValue(gp, f.getEntryPoint());
            if (rv != null && rv.hasValue()) { gpValue = rv.getUnsignedValue().longValue(); haveGp = true; }
            Address entry = f.getEntryPoint();
            List<Address> jrs = new ArrayList<>();
            InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (it.hasNext()) {
                Instruction in = it.next();
                String jm = in.getMnemonicString();
                if (jm.startsWith("_")) jm = jm.substring(1);
                if (!jm.equals("jr")) continue;
                Register jreg = null;
                for (Object o : in.getOpObjects(0)) if (o instanceof Register) jreg = (Register) o;
                if (jreg == null || jreg.getName().equals("ra")) continue;
                jrs.add(in.getAddress());
            }
            boolean changed = false;
            for (Address jr : jrs) {
                Instruction in = getInstructionAt(jr);
                if (in == null) continue;
                // Ghidra may already hold computed-jump references built from the
                // corrupted table (see above); they are wrong, so drop them and
                // rebuild from the real entries. If the table cannot be recovered
                // the old references are put back.
                List<Reference> old = new ArrayList<>();
                for (Reference r : in.getReferencesFrom())
                    if (r.getReferenceType() == RefType.COMPUTED_JUMP) old.add(r);
                for (Reference r : old) in.removeOperandReference(r.getOperandIndex(), r.getToAddress());
                int n = recover(f, jr);
                if (n > 0) { fixed++; changed = true; }
                else {
                    skipped++;
                    for (Reference r : old)
                        in.addOperandReference(r.getOperandIndex(), r.getToAddress(), r.getReferenceType(), r.getSource());
                }
            }
            if (changed) CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor);
        }
        println("IrixJumpTables: " + fixed + " table(s) recovered, " + skipped + " left alone");
    }

    // One table entry: original file bytes for a shared object, memory image
    // for a relocatable object.
    private long readEntry(Address a, long width) throws Exception {
        if (relocatable)
            return width == 8 ? mem.getLong(a) : (mem.getInt(a) & 0xffffffffL);
        MemoryBlock b = mem.getBlock(a);
        for (MemoryBlockSourceInfo si : b.getSourceInfos()) {
            if (!si.contains(a)) continue;
            long off = si.getFileBytesOffset(a);
            if (off < 0) continue;
            FileBytes fb = si.getFileBytes().orElseThrow();
            long v = 0;
            for (int i = 0; i < width; i++) v = (v << 8) | (fb.getOriginalByte(off + i) & 0xffL);
            return v;
        }
        throw new MemoryAccessException("no file bytes at " + a);
    }

    private int recover(Function f, Address jrAddr) throws Exception {
        List<Instruction> win = new ArrayList<>();
        Instruction cur = getInstructionAt(jrAddr);
        for (int i = 0; i < 24 && cur != null; i++) {
            win.add(0, cur);
            cur = cur.getPrevious();
        }
        Instruction jr = win.get(win.size() - 1);
        String tgtReg = null;
        for (Object o : jr.getOpObjects(0)) if (o instanceof Register) tgtReg = ((Register) o).getName();
        Map<String, Long> val = new HashMap<>();
        long width = 4;
        Integer bound = null;
        String idxReg = null;
        Long base = null;
        // o32 dispatch: the entry load carries the low half of the table address
        // as its displacement, and the entry is an offset from gp, added to gp
        // before the jr. tableReg holds base + scaled index, loadedReg the entry.
        String tableReg = null, loadedReg = null;
        long disp = 0;
        boolean gpRel = false;
        for (Instruction in : win) {
            // A delay-slot instruction's mnemonic carries a leading underscore.
            String m = in.getMnemonicString();
            if (m.startsWith("_")) m = m.substring(1);
            if (m.equals("nop")) continue;
            Register[] r = new Register[3];
            Scalar s = null;
            for (int k = 0; k < in.getNumOperands(); k++) {
                for (Object o : in.getOpObjects(k)) {
                    if (o instanceof Register && k < 3 && r[k] == null) r[k] = (Register) o;
                    if (o instanceof Scalar) s = (Scalar) o;
                }
            }
            switch (m) {
                case "lui": if (r[0] != null && s != null) val.put(r[0].getName(), s.getSignedValue() << 16); break;
                case "li": if (r[0] != null && s != null) val.put(r[0].getName(), s.getSignedValue()); break;
                case "addiu": case "daddiu": case "ori": {
                    if (r[0] == null || r[1] == null || s == null) break;
                    Long b = r[1].getName().equals("zero") ? Long.valueOf(0) : val.get(r[1].getName());
                    if (b != null) val.put(r[0].getName(), m.equals("ori") ? (b | s.getUnsignedValue()) : b + s.getSignedValue());
                    else val.remove(r[0].getName());
                    break; }
                case "move": case "or": case "addu": case "daddu": {
                    if (r[0] == null) break;
                    Register a = r[1], b = r[2];
                    if (loadedReg != null && m.equals("addu") && a != null && b != null
                        && ((a.getName().equals(loadedReg) && b.getName().equals("gp"))
                            || (b.getName().equals(loadedReg) && a.getName().equals("gp")))) {
                        // entry + gp: the table holds gp-relative offsets.
                        loadedReg = r[0].getName();
                        gpRel = true;
                        break;
                    }
                    if (a == null) { val.remove(r[0].getName()); break; }
                    Long va = a == null ? null : (a.getName().equals("zero") ? Long.valueOf(0) : val.get(a.getName()));
                    Long vb = b == null ? Long.valueOf(0) : (b.getName().equals("zero") ? Long.valueOf(0) : val.get(b.getName()));
                    if (m.equals("move")) { if (va != null) val.put(r[0].getName(), va); else val.remove(r[0].getName()); break; }
                    if (va != null && vb != null) { val.put(r[0].getName(), va + vb); break; }
                    if ((va != null) ^ (vb != null)) {
                        // base + scaled index: the known side is the table base.
                        String unknown = va == null ? a.getName() : (b == null ? "?" : b.getName());
                        base = va != null ? va : vb;
                        idxReg = unknown;
                        tableReg = r[0].getName();
                        val.remove(r[0].getName());
                        break;
                    }
                    val.remove(r[0].getName());
                    break; }
                case "sltiu": if (s != null) { bound = (int) s.getUnsignedValue(); } break;
                case "lw": case "ld": {
                    if (r[0] == null) break;
                    // gp-relative slot read from the image
                                        Register gpBase = null;
                    for (Object o : in.getOpObjects(1)) if (o instanceof Register) gpBase = (Register) o;
                    if (gpBase != null && gpBase.getName().equals("gp") && haveGp && s != null) {
                        Address slot = toAddr(gpValue + s.getSignedValue());
                        try {
                            // GOT entries are final addresses in the file; read them the
                            // same way as table entries.
                            val.put(r[0].getName(), readEntry(slot, m.equals("lw") ? 4 : 8));
                        } catch (Exception e) { val.remove(r[0].getName()); }
                    } else {
                        val.remove(r[0].getName());
                        if (gpBase != null && tableReg != null && gpBase.getName().equals(tableReg)) {
                            // the entry load: base + index, plus the displacement
                            disp = s == null ? 0 : s.getSignedValue();
                            width = m.equals("ld") ? 8 : 4;
                            loadedReg = r[0].getName();
                        } else if (r[0].getName().equals(tgtReg)) width = m.equals("ld") ? 8 : 4;
                    }
                    break; }
                default:
                    // Shifts and compares write r[0]; stores (sw, sd, ...) only read it.
                    boolean writesDest = m.startsWith("sll") || m.startsWith("dsll") || m.startsWith("sra")
                        || m.startsWith("srl") || m.startsWith("dsra") || m.startsWith("dsrl")
                        || m.startsWith("slt") || !(m.startsWith("s") || m.startsWith("b"));
                    if (r[0] != null && writesDest) val.remove(r[0].getName());
            }
        }
        if (base == null || base == 0 || bound == null) {
            if (bound != null)
                println("IrixJumpTables: " + f.getName() + " jr at " + jrAddr + ": bound " + bound
                    + " but no table base the evaluator could follow (vals " + val + ")");
            return 0;
        }
        base += disp;
        int n = bound;
        List<Address> targets = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            Address a = toAddr(base + i * width);
            long t;
            try { t = readEntry(a, width); }
            catch (Exception e) { println("IrixJumpTables: " + f.getName() + " table unreadable at " + a); return 0; }
            if (gpRel) {
                if (!haveGp) { println("IrixJumpTables: " + f.getName() + " gp-relative table at " + toAddr(base) + " but gp is unknown; run IrixGp.java first"); return 0; }
                t = gpValue + (int) t;
            }
            Address ta = toAddr(t);
            MemoryBlock b = mem.getBlock(ta);
            if (b == null || !b.isExecute()) {
                println("IrixJumpTables: " + f.getName() + " entry " + i + " = " + Long.toHexString(t) + " is not code; table at " + toAddr(base) + " rejected");
                return 0;
            }
            targets.add(ta);
        }
        for (Address ta : targets) {
            disassemble(ta);
            jr.addOperandReference(0, ta, RefType.COMPUTED_JUMP, SourceType.ANALYSIS);
        }
        // Tell the decompiler the destinations, in case order, so it prints a
        // switch rather than treating the jump as a call.
        new JumpTable(jrAddr, new ArrayList<>(targets), true, 0).writeOverride(f);
        println("IrixJumpTables: " + f.getName() + " jr at " + jrAddr + ": " + n + " entries of " + width
            + (gpRel ? " bytes (gp-relative) from " : " bytes from ") + toAddr(base) + " (" + new HashSet<>(targets).size() + " distinct targets)");
        return n;
    }
}
