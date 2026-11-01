# Ghidra scripts for IRIX code, and when to use them

Two tools read the shipped IRIX binaries: the assembly-to-C pipeline in `scripts/` (`spimdisasm` objects and `m2c`, here "the pipeline") and Ghidra's headless analyzer with the decompiler. Nothing here is specific to one graphics family: the method, the failure modes and the scripts in this directory apply to any IRIX MIPS binary (o32, N32, 64-bit, relocatable kernel objects). The `.java` files and this file are the same in every graphics workspace. Anything that depends on one family belongs in that workspace's own notes.

## Recommendation

| Job | Use | Why |
|---|---|---|
| Read one named function as C, fast, in a build with symbols or DWARF | the pipeline | 0.1 to 0.7 s a function, structured output, floating-point and bit-field code is usually right, a one-struct context file turns offsets into field names |
| Read a function the pipeline cannot reach: static function in a stripped library, 64-bit or o32 library | Ghidra | it finds functions from code flow, needs no symbol, and loads o32, N32, N64 and relocatable objects natively |
| Switch statements through a table | Ghidra with `IrixJumpTables.java` | neither tool recovers an IRIX table unaided; with the script Ghidra gets the whole body and every case, the pipeline needs a hand-written table label per switch |
| Find every caller, every store into a register window, every data reference | Ghidra | constant folding follows an offset held in a register across calls; a text pattern on the assembly misses those |
| Call graph of an entry point | either | direct calls are identical in both; Ghidra adds callers and counts unresolved indirect calls |
| Name the fields of a state record | either | both take one struct definition and print the same field names |
| Float-heavy leaf code | the pipeline, then Ghidra as a check | the pipeline resolves float literals inline when it can; Ghidra shows them as data labels, not values |
| Bulk text for diffing or grepping | the pipeline | committed `asm/` and `decomp/` trees, deterministic, no project state |

Rules of thumb. Use the pipeline first for anything it can reach, and read its output against the assembly when the function has a jump table, a float literal or a call to a function in the same object. Use Ghidra when the pipeline fails or the question spans the whole binary. Always run both Ghidra scripts (`IrixGp.java`, `IrixJumpTables.java`) before trusting a Ghidra switch or a global reference in IRIX code. Neither tool names a static function in a stripped build; the name has to come from DWARF in a sibling build or from the documentation.

## What only Ghidra offers

Cross-references to a register window. A driver often stores every board register through one helper whose address argument is a per-pipe base word plus a constant. `FindWindowStores.java` lists each call of that helper with the decompiler's folded offset, across every object given to one headless run. It catches stores where the offset register is set earlier than the call, which a text pattern on the assembly misses, and it misses a store when a base held across a loop joins two values so the offset does not fold. Neither is complete alone; use Ghidra to find sites and a text pattern to cross-check.

Code that has no helper dereferences the base itself. Run the same script with helper `-` and it lists every load and store, each with its address folded into a base expression and a constant offset, and a tag: `field` (the base is one load from a record), `chain` (two or more nested loads, with a scaled index between them where an array of per-owner pointers is walked) or `window` (no base: a constant address, folded to its physical address when it is a kernel-segment or XKPHYS constant). A regular expression over the base expression picks one chain out of many, and the range arguments pick one window. The script's opening comment gives the arguments and the expression syntax. The base expression records which fields and indexes were followed, so two chains that look alike in the offsets can be told apart: a chain that ends in a different record than the register window, reached through another array's slot number, shows a different expression, and a site found only by shape is not a register until the expression is checked against the code that sets the base up.

Call graph. `DumpCallEdges.java` dumps caller and callee per function and the indirect calls it could not resolve. For direct calls Ghidra adds nothing over a `grep` of `jal` over the assembly; it adds callers, unresolved indirect-call counts per function and, with `IrixJumpTables.java`, the destinations of switch tables.

Structure type propagation. `ApplyStruct.java` gives functions a typed first parameter from a C header; the pipeline takes the same header as `--context`. Both print the same field names. The pipeline needs the N32 target (`-t mipsn32`) for 64-bit objects once a context file declares 8-byte fields: with `-t mips` a 64-bit pointer takes two argument slots and the output has "read from unset register" errors. Ghidra needs the parameter list set (it has no stored signature for these functions) and a calling convention warning appears; otherwise equal. Ghidra keeps the type in the project, so one definition applies to later functions; the pipeline takes the context on every call.

## Failures and limits of the tools

Pipeline (as shipped):

- A jump table is not usable: the extractors emit the table words but leave the load unreferenced unless a base address is passed (`JTBL_BASE`) for N32/64-bit libraries, and the kernel and X-module extractors have no such option. m2c stops with "unable to determine jump table".
- The o32 and 64-bit library extractions are one large file. A single branch the parser rejects (`bnel t7,$at,sym-0xa18`) fails the whole file, so every function in it fails.
- Static functions have no symbol in the stripped builds and are not extracted at all.
- Calls to a same-object function that has no symbol of its own take the nearest preceding symbol's name.
- X-module assembly keeps GOT loads raw, so global and call targets are unresolved.
- The generated library and module runner scripts use the N32 target for every build.

Ghidra (default import):

- The DWARF analyzer fails with an end-of-file error on these DWARF-2 objects, so no statics are named.
- For the shared objects the loader applies the REL32 relocations to jump-table entries that already hold final addresses, so every entry is wrong (a constant added to each) and switch analysis gives up with "could not emulate address calculation".
- Relocatable kernel objects have no global pointer value. The loader rewrites each gp-relative immediate for a pointer it does not keep, so `unaff_gp + off` stays unresolved and the table base of a kernel switch cannot be found.
- The decompiler infers call prototypes: a call to an external whose callee has no definition can lose its last argument.
- A pointer to a table in `.rodata` that has no symbol of its own is named after the nearest string.

## Seeing every store to a command window

The decompiler treats a store to a constant address as a write to a global variable, and a later store to the same address replaces the earlier one. A routine that sends ten words to a FIFO at a fixed process address decompiles to one assignment, or two. A store through a pointer is never merged, so a window reached through a pointer loaded from a record (or through the zero register plus a displacement) already decompiles in full.

`MarkVolatileWindows.java START-END[,START-END...]` fixes the constant-address case: it creates an uninitialized read/write block over each range (or marks an existing block) volatile, and the decompiler then keeps every access in order. Run it as a post-script before `DecompileFunctions.java`, with the window's process address range, for example `MarkVolatileWindows.java 10000-11000` for a FIFO at 0x10000. Ranges must lie outside the library's own blocks. Reads of the window are kept too. Check a routine by counting its non-stack `sw`/`sh`/`sb`/`swc1` instructions in the assembly against the assignments to the window in the decompile; they match. Measured on the IP30 N32 `__glOdysseySetProgram`: 31 stores in the assembly to the FIFO, 2 in the default decompile, 31 with the script. Measured on a pointer-based sender (Kona `konDrawSolidRects`, 14 stores through the FIFO pointer) and on Kona and CRIME libGLcore senders: the default decompile already matches the assembly, and the script changes nothing.

## Scripts

Each script has its use in the opening comment. Run inside an image that has Ghidra's `analyzeHeadless`; create the project directory first (`mkdir -p /tmp/gp`), pass `-deleteProject` to leave nothing behind, and give a script path with `-scriptPath 'dir1;dir2'` when scripts live in more than one directory.

| Script | Run as | Does |
|---|---|---|
| `DecompileFunctions.java` | post-script | decompiles named functions (or `@0xADDR` for static ones) to a file with size and time per function |
| `IrixGp.java` | pre-script for shared objects, pre- or post-script for relocatable objects | sets gp and marks `.got`, `.rodata` and small-data blocks read-only. Shared objects: gp from the function prologues (agrees with `.got + 0x7ff0`), with a function's own value running only to the next code symbol. Relocatable objects: gp from the R_MIPS_GPREL16 relocation records, which must all agree |
| `IrixJumpTables.java` | post-script, after `IrixGp.java` | finds the table base and case count behind each `jr`, reads the entries from the file's original bytes (shared objects) or the relocated image (relocatable objects), registers a jump-table override so the decompiler prints a `switch`, and re-flows the function body. Handles absolute entries and, for o32, entries that are offsets from gp |
| `FindWindowStores.java` | post-script | lists calls of a store helper with the folded base-plus-offset address, or with helper `-` every load and store with its base tag (`field`, `chain`, `window`), base expression and offset |
| `MarkVolatileWindows.java` | post-script, before the decompile script | declares address ranges volatile so the decompiler prints every store to a command window at a fixed address |
| `DumpCallEdges.java` | post-script | dumps call edges and unresolved indirect calls |
| `ApplyStruct.java` | post-script, before the decompile script | gives functions a typed first parameter from a C header |

How the two IRIX scripts decide.

- Relocatable kernel objects. Ghidra rewrites each gp-relative immediate to `target - gp` for one gp it does not record, and the same gp holds for the whole object. For a GPREL16 record the target is the symbol's address plus the addend held in the original instruction, and a section symbol adds the object's gp0 (`gp_value` of the register-info option) as well. Solving `gp = target - immediate` gives the same value from every record; the script prints how many agree. Guessing from the smallest immediate, as an earlier version did, held only when some access was to word 0 of the small-data block.
- o32 switches. The dispatch loads a table page from a GOT slot, scales the biased index, loads the entry with the low half of the table address as the load's displacement, adds gp and jumps. The entries are offsets from gp, so the target is gp plus the entry.
- N32, N64 and kernel switches. Same dispatch with absolute entries and no gp add.

Limits of the scripts, found in use:

- Jump-table case labels print as the table entry (a target address), because the selector is the loaded entry rather than the index. Map labels to indices by the entry order in the script's log line.
- Tables are recognised by one dispatch shape: a bound check with `sltiu`, a base from a GOT or small-data slot (plus a low half or a load displacement), base plus scaled index, a load, `jr`. Other shapes are reported and left alone; most are tail calls through a register and some are real switches.
- In a relocatable object an access to an undefined (external) symbol shows as a reference into the start of the image, because the loader gives the symbol no address. Read it as that external; the relocation records name it.
- Float literals stay as data labels (`DAT_addr`): marking the literal blocks read-only did not make the decompiler fold them.
- Entries that are neither absolute addresses nor offsets from gp are not handled.

## The export helpers

`ReBSimAdd`, `ReDecompileExport`, `ReMdebugImport`, `ReMipsGp` and `ReObjectSymbols` are the
scripts `tools/re-run --ghidra-export` drives: global-pointer seeding, `.mdebug` names, decompile
export as JSON and function-similarity records. The Ghidra image carries them under
`/opt/re-scripts`; `tools/README-analysis.md` describes their output.
