// Disassemble every bundle of every memory block and write one line per
// instruction: address and Ghidra's text for it.
// Args: OUTFILE
// @category IA64
import java.io.PrintWriter;
import java.math.BigInteger;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class DumpSlots extends GhidraScript {
	@Override
	protected void run() throws Exception {
		AddressSet all = new AddressSet();
		AddressSet starts = new AddressSet();
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			if (!b.isInitialized()) {
				continue;
			}
			all.add(b.getStart(), b.getEnd());
			for (Address a = b.getStart(); a.compareTo(b.getEnd()) < 0; a = a.add(16)) {
				starts.add(a);
			}
		}
		// Each bundle from its own start, so data between code still decodes.
		new DisassembleCommand(starts, all, true).applyTo(currentProgram, monitor);
		fillDeadSlots(starts);
		Listing listing = currentProgram.getListing();
		try (PrintWriter out = new PrintWriter(getScriptArgs()[0])) {
			for (Instruction in : listing.getInstructions(all, true)) {
				out.printf("%s\t%s%n", in.getAddress(), in.toString());
			}
		}
	}

	// Slots after a taken-always branch are never reached by flow; decode them
	// too, with the context the slot before would have handed on.
	private void fillDeadSlots(AddressSet starts) throws Exception {
		Listing listing = currentProgram.getListing();
		Memory mem = currentProgram.getMemory();
		ProgramContext ctx = currentProgram.getProgramContext();
		Register slot = ctx.getRegister("slot"), tmpl = ctx.getRegister("tmpl");
		Register ca = ctx.getRegister("ca"), cb = ctx.getRegister("cb");
		byte[] b = new byte[16];
		for (AddressRange r : starts) {
			for (Address a = r.getMinAddress(); a.compareTo(r.getMaxAddress()) <= 0; a = a.add(16)) {
				Address s1 = a.add(6), s2 = a.add(12);
				if (listing.getInstructionAt(s1) != null && listing.getInstructionAt(s2) != null) {
					continue;
				}
				if (mem.getBytes(a, b) != 16) {
					continue;
				}
				BigInteger v = new BigInteger(1, reverse(b));
				int t = v.intValue() & 0x1f;
				if (listing.getInstructionAt(s1) == null && listing.getCodeUnitContaining(s1) instanceof Data) {
					set(ctx, slot, s1, 1);
					set(ctx, tmpl, s1, t);
					set(ctx, ca, s1, v.shiftRight(46).intValue() & 0x3);
					disassemble(s1, a.add(15));
				}
				if (listing.getInstructionAt(s2) == null && listing.getCodeUnitContaining(s2) instanceof Data) {
					set(ctx, slot, s2, 2);
					set(ctx, tmpl, s2, t);
					set(ctx, cb, s2, v.shiftRight(87).intValue() & 0x1ff);
					disassemble(s2, a.add(15));
				}
			}
		}
	}

	private void disassemble(Address a, Address end) {
		new DisassembleCommand(new AddressSet(a), new AddressSet(a, end), true).applyTo(currentProgram, monitor);
	}

	private static void set(ProgramContext ctx, Register r, Address a, int v) throws Exception {
		ctx.setValue(r, a, a, BigInteger.valueOf(v));
	}

	private static byte[] reverse(byte[] b) {
		byte[] r = new byte[b.length];
		for (int i = 0; i < b.length; i++) {
			r[i] = b[b.length - 1 - i];
		}
		return r;
	}
}
