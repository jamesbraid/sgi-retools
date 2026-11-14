## Evidence order

For a register or behaviour fact, take it from the highest source that states it and grade it by that source:

1. IRIX source (public `irix-657m-src` tree): read it, write the fact in your own words, never copy source text, cite the path in the tree. A fact it defines is `established`.
2. Shipped binaries (PROMs, kernels, libraries): confirm the source matches what shipped, and the release differences (6.5.7 source, 6.5.22 and 6.5.30 binaries).
3. Public Linux, OpenBSD and NetBSD headers and drivers: `established` once the IRIX source confirms them.
4. Published SGI and vendor manuals.
5. Notes from other projects (other projects' datasheets, manual pages and emulator code): may confirm or contradict, never supply a fact. A fact resting only on one stays `unknown`, with the note named.

For machines with no IRIX source (SN2 Altix and Prism, IA-64 on SN1, Altix UV), SGI's own Linux platform code (`arch/ia64/sn/`, its `sn` headers, `arch/x86/platform/uv/` and the `uv` headers) and SGI-written Linux drivers for these platforms wherever they live (`drivers/misc/ioc4.c` and its headers, `drivers/char/snsc.c` and `snsc_event.c`, `drivers/char/mmtimer.c`, `drivers/misc/sgi-xp/`, `drivers/misc/sgi-gru/`, `drivers/sn/`, the SN-specific PCI providers) take step 1, cited by tree, tag and path, and SGI's ProPack binaries take step 2.

Reset values: `established` when the source states a power-on default or PROM code relies on a reset state; `inferred` when the PROM depends on a value before its first write (cite the PROM address); a read after firmware initialisation is not a reset value and can only rule values out; otherwise `unknown`. A physical hardware read is a last resort, needs the repository owner's approval, and counts as a reset value only for a register firmware provably never writes. Emulator runs are model behaviour, never hardware evidence.

Full text and the checks that enforce it: `retools/tools/README-analysis.md#evidence-order`.
