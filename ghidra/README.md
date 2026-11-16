# Ghidra

Everything we add to Ghidra lives here: processor modules for SGI's microcode engines and for IA-64,
loaders for firmware images, and scripts for IRIX objects.

- `processors/<name>/` is one instruction set each.
- `import/<name>/` lays out one kind of firmware image.
- `types/<name>/` holds data types for one device family.
- `scripts/` holds the Ghidra scripts any repository can use. [scripts/README.md](scripts/README.md)
  says when Ghidra beats the assembly-to-C pipeline and when it doesn't.

Each component has its own README, a `tests/run-ghidra.sh` that runs it in the Ghidra image, and a
`tests/check.py` that checks the result with plain Python. Read the component's README before using it.

## Running it

From a repository that has this toolbox as `retools/`:

```sh
retools/tools/re-run --ghidra-export IMAGE [OPTIONS]      # decompile, list or export one image
retools/tools/re-run --ghidra -- COMMAND                   # anything else in the Ghidra image
```

`retools/tools/re-run python3 retools/tools/ghidra-export.py --help` lists the export options: address
ranges, symbols, flat PROM images, ELF and PE objects.

## Adding a component

Add it here, under the layout above, with its README and both test scripts, even when only one repository
uses it so far. Scripts that read IRIX objects and don't belong to one hardware family go in `scripts/`.
