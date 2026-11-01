// Disassemble every word that holds a decoded record and write one line per
// instruction: word address, the 18-digit word, and Ghidra's text for it.
// Args: OUTFILE [FIRST LAST]
// @category GE11
import java.io.PrintWriter;
import java.math.BigInteger;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;

public class DumpListing extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		AddressSpace code = currentProgram.getAddressFactory().getAddressSpace("code");
		long n = currentProgram.getMemory().getBlock("code").getSize() / 8;
		Register valid = currentProgram.getRegister("fvalid");
		Register wtop = currentProgram.getRegister("fwtop");
		ProgramContext pc = currentProgram.getProgramContext();
		AddressSet todo = new AddressSet();
		Listing listing = currentProgram.getListing();
		for (long a = 0; a < n; a++) {
			Address ad = code.getAddress(8 * a);
			BigInteger v = pc.getValue(valid, ad, false);
			if (v != null && v.signum() != 0 && listing.getInstructionAt(ad) == null) {
				todo.add(ad);
			}
		}
		// Disassemble word by word without following flow, so every word is
		// decoded on its own, delay slots included.
		DisassembleCommand cmd = new DisassembleCommand(todo, todo, false);
		cmd.applyTo(currentProgram, monitor);
		try (PrintWriter out = new PrintWriter(args[0])) {
			for (long a = 0; a < n; a++) {
				Address ad = code.getAddress(8 * a);
				BigInteger v = pc.getValue(valid, ad, false);
				if (v == null || v.signum() == 0) {
					continue;
				}
				Instruction in = listing.getInstructionAt(ad);
				byte[] buf = new byte[8];
				currentProgram.getMemory().getBytes(ad, buf);
				BigInteger top = pc.getValue(wtop, ad, false);
				String w = String.format("%02x%016x", top == null ? 0 : top.intValue(), new BigInteger(1, buf));
				out.printf("%04x\t%s\t%s%n", a, w, in == null ? "<none>" : in.toString());
			}
		}
	}

}
