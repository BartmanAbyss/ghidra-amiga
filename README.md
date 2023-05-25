# ghidra-amiga
based on [ghidra_amiga_ldr](https://github.com/lab313ru/ghidra_amiga_ldr) by Vladimir Kononovich (No license)
and [ghidra-amiga-whdload](https://github.com/apparentlymart/ghidra-amiga-whdload) by Martin Atkins (MIT license)

see https://github.com/astrelsky/vscode-ghidra-skeleton

## Development
- create `data/amiga_ndk39.gdt` with the `amiga_ndk39.prf` C parser profile (put in `USER_HOME/.ghidra_10.1.5_PUBLIC/parseprofiles`). A few headers have been exluded due to parsing problems, and `pack.h` has been added to the start of the parsed headers to ensure correct struct alignment.

## Debugging
- start Ghidra; add `dist/ghidra_10.3_PUBLIC_20230525_ghidra-amiga.zip.zip` as Plugin, restart, Install Extension ...

## TODO
