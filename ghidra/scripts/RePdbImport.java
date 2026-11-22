/* Point Ghidra's PDB Universal analyzer at a .pdb for a PE image that has no CodeView record.
 *
 * A driver stripped to a separate .dbg and .pdb keeps the CodeView record in the .dbg, so the
 * analyzer finds no PDB information in the program and skips it. This pre-script copies the
 * PDB's own signature and age into the program information and names the file, then analysis
 * applies the types and symbols. It reads PDB 2.0 (VC6 era) and 7.0, except a PDB 2.0 whose
 * debug info is version 19960307 (see ghidra/README.md).
 *
 *   -preScript RePdbImport.java FILE.pdb
 *
 * Ghidra script, Apache-2.0 like Ghidra itself.
 *
 * @category RE
 */

import java.io.File;

import ghidra.app.plugin.core.analysis.PdbUniversalAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbIdentifiers;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbParser;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions;
import ghidra.framework.options.Options;

public class RePdbImport extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			throw new IllegalArgumentException("usage: RePdbImport <file.pdb>");
		}
		File file = new File(args[0]);
		PdbIdentifiers id;
		try (AbstractPdb pdb = PdbParser.parse(file, new PdbReaderOptions(), monitor)) {
			pdb.deserialize();
			id = pdb.getIdentifiers();
		}
		catch (PdbException e) {
			// The analyzer runs the same parse, so it would skip this file without a word.
			throw new IllegalArgumentException(file.getName() + ": Ghidra's PDB reader cannot " +
				"parse this file (" + e.getMessage() + "); see ghidra/README.md", e);
		}
		Options info = currentProgram.getOptions("Program Information");
		if (id.getGuid() != null) {
			info.setString("PDB Version", "RSDS");
			info.setString("PDB GUID", id.getGuid().toString());
		}
		else {
			info.setString("PDB Version", "NB10");
			info.setString("PDB Signature", Integer.toHexString(id.getSignature()).toUpperCase());
		}
		info.setString("PDB Age", Integer.toHexString(id.getAge()));
		info.setString("PDB File", file.getName());
		PdbUniversalAnalyzer.setPdbFileOption(currentProgram, file);
		PdbUniversalAnalyzer.setAllowUntrustedOption(currentProgram, true);
		println("RePdbImport: " + file.getName() + " signature/age " + id.getSignature() + "/" +
			id.getAge());
	}
}
