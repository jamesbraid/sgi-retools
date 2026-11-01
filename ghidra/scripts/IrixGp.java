// Give Ghidra the global pointer and constant tables IRIX position-independent
// MIPS code needs. Run it as a pre-script (before auto-analysis) so the
// analyzers and the decompiler see the values:
//
//   analyzeHeadless DIR proj -import FILE -preScript IrixGp.java ...
//
// What it does, and why Ghidra's default import does not:
//
//  1. gp. Shared objects (o32, N32, N64) load gp in each function prologue from
//     the entry address (t9) plus a constant, so one value covers the whole
//     object, and Ghidra's loader leaves it unset: every global then reads as
//     "unaff_gp + offset". The script decodes the prologue of every function
//     symbol (N32/N64: lui/addiu into a scratch register then addu gp,t9,reg;
//     o32: lui/addiu on gp then addu gp,gp,t9), takes the value most functions
//     agree on and checks it against .got + 0x7ff0. It sets gp over every
//     executable block. A function whose prologue gives a different value gets
//     its own setting. Stripped statics have no symbol and use the object value.
//  2. Constant tables. .got, .rodata and the small-data blocks are read-only in
//     practice, but the ELF flags them writable, so Ghidra will not fold a load
//     from them. The script clears the write flag on those blocks. GOT loads
//     then fold to the callee or data address and jump-table bases fold to the
//     table, which lets the switch analysis recover the table.
//  3. Relocatable kernel objects (kona.a members) have no GOT or gp value at
//     all: small data is reached by R_MIPS_GPREL16 relocations, and the loader
//     rewrites each gp-relative immediate for a gp it does not keep. The script
//     recovers that gp from the relocation records. For each GPREL16 record the
//     target is the symbol's address plus the addend held in the original
//     instruction (a section symbol also adds the object's gp0, the gp_value of
//     its register-info option), and the loader's immediate is target - gp, so
//     gp = target - immediate. Every record must give the same gp, which is the
//     check; the value is set over the executable blocks. Because it reads the
//     relocation table it can run before or after analysis. When the object has
//     no relocation records the script falls back to guessing from the
//     smallest gp-relative immediate (slot 0 of the small-data block), which is
//     right only when that access is to the first small-data word.
//
// Limits: one gp per object unless a prologue disagrees; a binary that sets gp
// by other means (hand-written assembly, a non-standard prologue) keeps the
// object value and may be wrong in that function. Output of the script is
// printed with the prefix "IrixGp:".
// @category RE
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.symbol.*;
import java.math.BigInteger;
import java.util.*;

public class IrixGp extends GhidraScript {
    private static final int T9 = 25, GP = 28;

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        Register gp = currentProgram.getRegister("gp");
        ProgramContext ctx = currentProgram.getProgramContext();
        boolean big = true;
        // Read-only constant blocks.
        for (MemoryBlock b : mem.getBlocks()) {
            String n = b.getName();
            if (n.equals(".got") || n.startsWith(".rodata") || n.equals(".srdata")
                || n.equals(".sdata") || n.equals(".lit4") || n.equals(".lit8")) {
                b.setWrite(false);
                println("IrixGp: " + n + " made read-only at " + b.getStart());
            }
        }
        boolean relocatable = mem.getBlock(".got") == null;
        if (relocatable) {
            MemoryBlock sd = mem.getBlock(".srdata");
            if (sd == null) sd = mem.getBlock(".sdata");
            if (sd == null) { println("IrixGp: no small-data block, nothing to set"); return; }
            if (gpFromRelocations()) return;
            // Ghidra rewrites each gp-relative immediate (relocation against the
            // small-data block) assuming some gp it does not record. Every such
            // access lands in the block, so the smallest immediate is slot 0:
            // gp = block start - smallest immediate. All accesses must then fall
            // inside the block, which is the check.
            long minImm = Long.MAX_VALUE, maxImm = Long.MIN_VALUE;
            int uses = 0;
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
                while (it.hasNext()) {
                    Instruction in = it.next();
                    if (in.getNumOperands() < 2) continue;
                    boolean gpBase = false; Long imm = null;
                    for (Object o : in.getOpObjects(1)) {
                        if (o instanceof Register && ((Register) o).getName().equals("gp")) gpBase = true;
                        if (o instanceof ghidra.program.model.scalar.Scalar)
                            imm = ((ghidra.program.model.scalar.Scalar) o).getSignedValue();
                    }
                    if (gpBase && imm != null) {
                        minImm = Math.min(minImm, imm); maxImm = Math.max(maxImm, imm); uses++;
                    }
                }
            }
            if (uses == 0) { println("IrixGp: relocatable object with no gp-relative access"); return; }
            long v = sd.getStart().getOffset() - minImm;
            boolean fits = v + maxImm < sd.getEnd().getOffset();
            if (!fits) {
                println("IrixGp: relocatable object, " + uses + " gp-relative accesses; the smallest"
                    + " immediate is not slot 0 of " + sd.getName() + ", gp left unset");
                return;
            }
            for (MemoryBlock b : mem.getBlocks())
                if (b.isExecute())
                    ctx.setValue(gp, b.getStart(), b.getEnd(), BigInteger.valueOf(v));
            println("IrixGp: relocatable object, " + uses + " gp-relative accesses, gp = "
                + Long.toHexString(v) + " (all inside " + sd.getName() + ")");
            return;
        }
        // Shared object: decode prologues.
        Map<Long, Integer> votes = new HashMap<>();
        Map<Address, Long> perFunc = new HashMap<>();
        SymbolIterator it = currentProgram.getSymbolTable().getSymbolIterator(true);
        int seen = 0;
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.getSymbolType() != SymbolType.FUNCTION && s.getSymbolType() != SymbolType.LABEL) continue;
            Address a = s.getAddress();
            MemoryBlock b = mem.getBlock(a);
            if (b == null || !b.isExecute()) continue;
            Long v = prologueGp(mem, a);
            if (v == null) continue;
            seen++;
            votes.merge(v, 1, Integer::sum);
            perFunc.put(a, v);
        }
        long best = 0; int bestN = 0;
        for (Map.Entry<Long, Integer> e : votes.entrySet())
            if (e.getValue() > bestN) { best = e.getKey(); bestN = e.getValue(); }
        MemoryBlock got = mem.getBlock(".got");
        long gotGp = got.getStart().getOffset() + 0x7ff0;
        println("IrixGp: prologues decoded " + seen + ", distinct gp values " + votes.size()
            + ", most common " + Long.toHexString(best) + " (" + bestN + "), .got+0x7ff0 = "
            + Long.toHexString(gotGp) + (best == gotGp ? " (agree)" : " (DISAGREE)"));
        if (bestN == 0) best = gotGp;
        for (MemoryBlock b : mem.getBlocks())
            if (b.isExecute())
                ctx.setValue(gp, b.getStart(), b.getEnd(), BigInteger.valueOf(best));
        // Functions whose prologue disagrees. Each one's value runs to the next
        // code symbol, so it cannot leak into a neighbour that agrees with the
        // object value.
        TreeSet<Address> starts = new TreeSet<>();
        SymbolIterator si = currentProgram.getSymbolTable().getSymbolIterator(true);
        while (si.hasNext()) {
            Symbol s = si.next();
            if (s.getSymbolType() != SymbolType.FUNCTION && s.getSymbolType() != SymbolType.LABEL) continue;
            MemoryBlock b = mem.getBlock(s.getAddress());
            if (b != null && b.isExecute()) starts.add(s.getAddress());
        }
        int odd = 0;
        for (Map.Entry<Address, Long> e : perFunc.entrySet()) {
            if (e.getValue() == best) continue;
            Address a = e.getKey();
            MemoryBlock b = mem.getBlock(a);
            Address nxt = starts.higher(a);
            Address end = (nxt == null || !b.contains(nxt)) ? b.getEnd() : nxt.subtract(1);
            ctx.setValue(gp, a, end, BigInteger.valueOf(e.getValue()));
            odd++;
        }
        println("IrixGp: " + odd + " function(s) with their own gp");
    }

    // gp0, the gp the assembler assumed: gp_value of the register-info option
    // (.MIPS.options, 64-bit and N32 objects) or of .reginfo (32-bit objects).
    private long gp0() throws Exception {
        Memory mem = currentProgram.getMemory();
        MemoryBlock ri = mem.getBlock(".reginfo");
        if (ri != null && ri.getSize() >= 24) return mem.getInt(ri.getEnd().subtract(3)) & 0xffffffffL;
        MemoryBlock op = mem.getBlock(".MIPS.options");
        if (op == null) return 0;
        Address a = op.getStart();
        while (a.compareTo(op.getEnd()) < 0) {
            int kind = mem.getByte(a) & 0xff, size = mem.getByte(a.add(1)) & 0xff;
            if (size < 8) break;
            if (kind == 1) // ODK_REGINFO: gprmask, (pad,) cprmask[4], gp_value
                return size >= 40 ? mem.getLong(a.add(size - 8)) : (mem.getInt(a.add(size - 4)) & 0xffffffffL);
            a = a.add(size);
        }
        return 0;
    }

    // Recover gp of a relocatable object from its R_MIPS_GPREL16 records.
    // Returns false when there are none to use.
    private boolean gpFromRelocations() throws Exception {
        Memory mem = currentProgram.getMemory();
        long gp0 = gp0();
        Map<Long, Integer> votes = new HashMap<>();
        for (Relocation r : (Iterable<Relocation>) () -> currentProgram.getRelocationTable().getRelocations()) {
            if (r.getType() != 7 || r.getBytes() == null || r.getBytes().length < 4) continue;
            byte[] by = r.getBytes();
            long addend = (short) (((by[2] & 0xff) << 8) | (by[3] & 0xff));
            long cur = mem.getShort(r.getAddress().add(2));
            String name = r.getSymbolName();
            long sym;
            MemoryBlock blk = name == null ? null : mem.getBlock(name);
            if (blk != null && name.startsWith(".")) { sym = blk.getStart().getOffset(); addend += gp0; }
            else {
                Long a = null;
                if (name != null)
                    for (Symbol s : currentProgram.getSymbolTable().getSymbols(name)) { a = s.getAddress().getOffset(); break; }
                if (a == null) continue;
                sym = a;
            }
            votes.merge(sym + addend - cur, 1, Integer::sum);
        }
        if (votes.isEmpty()) return false;
        long best = 0; int bestN = 0, total = 0;
        for (Map.Entry<Long, Integer> e : votes.entrySet()) {
            total += e.getValue();
            if (e.getValue() > bestN) { best = e.getKey(); bestN = e.getValue(); }
        }
        ProgramContext ctx = currentProgram.getProgramContext();
        Register gp = currentProgram.getRegister("gp");
        for (MemoryBlock b : mem.getBlocks())
            if (b.isExecute())
                ctx.setValue(gp, b.getStart(), b.getEnd(), BigInteger.valueOf(best));
        println("IrixGp: relocatable object, gp = " + Long.toHexString(best) + " from " + bestN + " of "
            + total + " gp-relative relocations (gp0 " + Long.toHexString(gp0) + ")"
            + (bestN == total ? ", all agree" : ", " + (votes.size() - 1) + " other value(s): CHECK"));
        return true;
    }

    // gp a function computes in its prologue, or null if it computes none.
    private Long prologueGp(Memory mem, Address entry) {
        long[] lui = new long[32];
        boolean[] haveLui = new boolean[32];
        long[] val = new long[32];
        boolean[] have = new boolean[32];
        try {
            for (int i = 0; i < 12; i++) {
                int w = mem.getInt(entry.add(4L * i), true);
                int op = w >>> 26, rs = (w >> 21) & 31, rt = (w >> 16) & 31, rd = (w >> 11) & 31;
                int imm = (short) (w & 0xffff);
                if (op == 0x0f) { val[rt] = ((long) imm) << 16; have[rt] = true; }
                else if ((op == 0x09 || op == 0x19) && have[rs]) { val[rt] = val[rs] + imm; have[rt] = true; }
                else if (op == 0 && ((w & 0x3f) == 0x21 || (w & 0x3f) == 0x2d) && rd == GP) {
                    int other = rs == T9 ? rt : (rt == T9 ? rs : -1);
                    if (other >= 0 && have[other])
                        return (entry.getOffset() + val[other]) & 0xffffffffL
                            | (entry.getOffset() & ~0xffffffffL);
                    return null;
                }
            }
        } catch (MemoryAccessException e) { }
        return null;
    }
}
