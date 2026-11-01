// Write what the ARM import produced, for tests/check.py: one line per
// function (F address name), per token-list entry (T token address entry
// handler handler-function), per data table (D address type) and a count of
// references into each memory block (B block references).
// Args: OUTFILE
// @category KONA
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

public class DumpArm extends GhidraScript {
	@Override
	protected void run() throws Exception {
		Memory mem = currentProgram.getMemory();
		Listing listing = currentProgram.getListing();
		try (PrintWriter out = new PrintWriter(getScriptArgs()[0])) {
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				out.printf("F\t0x%08x\t%s%n", f.getEntryPoint().getOffset(), f.getName());
			}
			SymbolIterator it = currentProgram.getSymbolTable().getSymbolIterator("icu_list_*", true);
			for (Symbol s : it) {
				Address ad = s.getAddress();
				String[] p = s.getName().split("_");
				long w = mem.getInt(ad) & 0xffffffffL;
				String h = "-", hf = "-";
				if ((w & 1) == 0 && w != 0xffffffffL) {
					long hv = mem.getInt(ad.add(4)) & 0xffffffffL;
					h = String.format("0x%08x", hv);
					Function f = getFunctionAt(ad.getNewAddress(hv));
					hf = f == null ? "-" : f.getName();
				}
				out.printf("T\t0x%s\t0x%08x\t0x%08x\t%s\t%s%n", p[2], ad.getOffset(), w, h, hf);
			}
			for (Data d : listing.getDefinedData(true)) {
				if (d.isArray() || d.isStructure()) {
					out.printf("D\t0x%08x\t%s%n", d.getAddress().getOffset(), d.getDataType().getName());
				}
			}
			ReferenceManager rm = currentProgram.getReferenceManager();
			for (MemoryBlock b : mem.getBlocks()) {
				int n = 0;
				AddressIterator ai = rm.getReferenceDestinationIterator(new AddressSet(b.getStart(), b.getEnd()), true);
				while (ai.hasNext()) {
					n += rm.getReferenceCountTo(ai.next());
				}
				out.printf("B\t%s\t0x%08x\t%d%n", b.getName(), b.getStart().getOffset(), n);
			}
		}
	}
}
