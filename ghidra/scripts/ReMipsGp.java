/* Seed the MIPS global pointer, and the entry point, before Ghidra analyses.
 *
 * Runs as a headless -preScript, so it lands between import and analysis.
 * That order is the whole point. An ELF tells Ghidra its gp value; a PROM
 * payload is a bare block of bytes, so without this the MIPS analyser starts
 * with gp unknown, and every `ld t9, -0x7aa0(gp)` feeding a `jalr t9` stays an
 * unresolved computed call. Ghidra's own MipsAddressAnalyzer reads gp out of
 * the program context when a value is set there, which is what this writes.
 *
 * The value is recovered from the image itself: MIPS has no instruction that
 * loads a 64-bit constant, so a compiler builds one with a fixed shape --
 * lui, then a run of daddiu/ori/dsll into the same register. Find those runs
 * writing to gp, evaluate each with real 64-bit MIPS semantics, and take the
 * value the image agrees on most often. A caller that already knows the value
 * passes it as the first argument and this scan is skipped; `loader` says an
 * ELF was read by Ghidra's own loader, which has the object's own answer
 * already and must not be argued with by a scan over its bytes.
 *
 * The second argument is where execution starts, or `-` where whatever loaded
 * the file established that itself. A file read as bytes has no entry point at
 * all, so nothing tells Ghidra where the code is and its analysis has to find
 * the first instruction by pattern.
 *
 * Ghidra script, Apache-2.0 like Ghidra itself.
 *
 * @category RE
 */

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.MemoryBlock;

public class ReMipsGp extends GhidraScript {

	private static final int GP = 28;

	/* How far past either end of the image a recovered gp may still be
	 * believed. The global pointer addresses a table near the image, not
	 * an arbitrary address, so a candidate far outside it came from bytes
	 * that merely decode like a constant build-up. */
	private static final long PLAUSIBLE_SLACK = 64L * 1024 * 1024;

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String asked = args.length > 0 ? args[0] : "auto";
		seedGlobalPointer(asked);
		seedEntryPoint(args.length > 1 ? args[1] : "-");
	}

	private void seedGlobalPointer(String asked) throws Exception {
		Register gp = currentProgram.getRegister("gp");
		if (gp == null) {
			println("re-gp: no gp register in " +
				currentProgram.getLanguageID() + "; nothing to seed");
			return;
		}
		/* `none` leaves gp unset so the resolution the seeding buys can be
		 * measured rather than asserted. It is the control arm, not an
		 * option anyone should run for an answer. `loader` says the object
		 * came in through a loader that read the value out of the object. */
		if (asked.equals("none")) {
			println("re-gp: gp left unset on request");
			return;
		}
		if (asked.equals("loader")) {
			println("re-gp: gp left to whatever loaded the object");
			return;
		}
		long value;
		String how;
		if (!asked.equals("auto")) {
			value = new BigInteger(asked.replaceFirst("^0[xX]", ""), 16).longValue();
			how = "supplied";
		}
		else {
			Long found = recover();
			if (found == null) {
				println("re-gp: no gp materialization found; " +
					"leaving gp unset");
				return;
			}
			value = found;
			how = "recovered";
		}

		BigInteger unsigned = new BigInteger(Long.toUnsignedString(value));
		ProgramContext context = currentProgram.getProgramContext();
		for (AddressRange range : currentProgram.getMemory().getAddressRanges()) {
			context.setValue(gp, range.getMinAddress(), range.getMaxAddress(),
				unsigned);
		}
		println(String.format("re-gp: %s gp = 0x%016x", how, value));
	}

	/* Where the code starts, for a file read as bytes. A PROM's first word is
	 * its reset vector by definition of the part and an ECOFF header states
	 * its own entry, so say so: disassembly from there walks the vector table
	 * and the flow behind it instead of guessing at it. `-` means the loader
	 * established the entry point itself, which Ghidra's ELF loader does. */
	private void seedEntryPoint(String where) throws Exception {
		if (where.equals("-")) {
			println("re-gp: entry point left to whatever loaded the object");
			return;
		}
		Address entry = currentProgram.getAddressFactory()
			.getDefaultAddressSpace().getAddress(
				new BigInteger(where.replaceFirst("^0[xX]", ""), 16).longValue());
		if (entry == null || !currentProgram.getMemory().contains(entry)) {
			println("re-gp: " + where + " is not in the loaded image; " +
				"leaving the entry point to analysis");
			return;
		}
		currentProgram.getSymbolTable().addExternalEntryPoint(entry);
		if (disassemble(entry)) {
			println("re-gp: disassembled from the entry point at " + entry);
		}
		else {
			println("re-gp: nothing decodes at " + entry +
				"; leaving the entry point to analysis");
		}
	}

	/* The most-repeated plausible gp value built anywhere in the image. */
	private Long recover() throws Exception {
		Map<Long, Integer> votes = new HashMap<>();
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (!block.isInitialized()) {
				continue;
			}
			Address start = block.getStart();
			long length = block.getSize() & ~3L;
			byte[] bytes = new byte[(int) Math.min(length, Integer.MAX_VALUE)];
			block.getBytes(start, bytes);
			for (int i = 0; i + 4 <= bytes.length; i += 4) {
				long word = word(bytes, i);
				if (opcode(word) != 0x0f || rt(word) != GP || rs(word) != 0) {
					continue;   // not `lui gp, imm`
				}
				Long built = evaluate(bytes, i);
				if (built != null && plausible(built)) {
					votes.merge(built, 1, Integer::sum);
				}
			}
		}
		Long best = null;
		int bestVotes = 0;
		for (Map.Entry<Long, Integer> vote : votes.entrySet()) {
			if (vote.getValue() > bestVotes) {
				best = vote.getKey();
				bestVotes = vote.getValue();
			}
		}
		if (best != null) {
			println(String.format(
				"re-gp: %d candidate value(s), winner 0x%016x with %d sites",
				votes.size(), best, bestVotes));
		}
		return best;
	}

	/* Evaluate the constant build-up that starts with the `lui gp` at `at`.
	 * Returns null when the run is a bare lui with nothing following it,
	 * which carries too little evidence to be worth a vote. */
	private Long evaluate(byte[] bytes, int at) {
		long value = (long) (short) (word(bytes, at) & 0xffff) << 16;
		int steps = 0;
		for (int i = at + 4; i + 4 <= bytes.length && i < at + 40; i += 4) {
			long word = word(bytes, i);
			int op = opcode(word);
			int immediate = (short) (word & 0xffff);
			if ((op == 0x09 || op == 0x19) && rt(word) == GP && rs(word) == GP) {
				value += immediate;            // addiu / daddiu gp, gp, imm
				if (op == 0x09) {
					value = (int) value;       // addiu truncates and sign-extends
				}
			}
			else if (op == 0x0d && rt(word) == GP && rs(word) == GP) {
				value |= word & 0xffff;        // ori gp, gp, imm
			}
			else if (op == 0 && rd(word) == GP && rt(word) == GP &&
				((word & 0x3f) == 0x38 || (word & 0x3f) == 0x3c)) {
				int amount = (int) ((word >> 6) & 0x1f);
				value <<= ((word & 0x3f) == 0x3c) ? amount + 32 : amount;
			}
			else {
				break;
			}
			steps++;
		}
		return steps == 0 ? null : value;
	}

	private boolean plausible(long value) {
		Address min = currentProgram.getMinAddress();
		Address max = currentProgram.getMaxAddress();
		if (min == null || max == null) {
			return false;
		}
		return Long.compareUnsigned(value, min.getOffset() - PLAUSIBLE_SLACK) >= 0 &&
			Long.compareUnsigned(value, max.getOffset() + PLAUSIBLE_SLACK) <= 0;
	}

	private static long word(byte[] bytes, int at) {
		return ((long) (bytes[at] & 0xff) << 24) | ((bytes[at + 1] & 0xff) << 16) |
			((bytes[at + 2] & 0xff) << 8) | (bytes[at + 3] & 0xff);
	}

	private static int opcode(long word) {
		return (int) (word >>> 26) & 0x3f;
	}

	private static int rs(long word) {
		return (int) (word >>> 21) & 0x1f;
	}

	private static int rt(long word) {
		return (int) (word >>> 16) & 0x1f;
	}

	private static int rd(long word) {
		return (int) (word >>> 11) & 0x1f;
	}
}
