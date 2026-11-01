// Write one line per record: record number and Ghidra's text for it.
// Args: OUTFILE
// @category ODSY
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class DumpListing extends GhidraScript {
	@Override
	protected void run() throws Exception {
		AddressSpace code = currentProgram.getAddressFactory().getAddressSpace("code");
		long n = currentProgram.getMemory().getBlock("code").getSize() / 8;
		Listing listing = currentProgram.getListing();
		try (PrintWriter out = new PrintWriter(getScriptArgs()[0])) {
			for (long a = 0; a < n; a++) {
				Instruction in = listing.getInstructionAt(code.getAddress(8 * a));
				out.printf("%04d\t%s%n", a, in == null ? "<none>" : in.toString());
			}
		}
	}
}
