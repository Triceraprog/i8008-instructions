This program generates all opcodes for the old and new syntax of the Intel 8008 processor.

Two source files are generated: one with the old syntax and one with the new syntax.

One output file is generated with the resulting binary code.

It is aimed as input for assemblers for this processor.
The output of an assembler should generate the same output for both source files, and almost the same output for binary files.

Differences can happen in the following cases:
- lowest bit of the `0b0000000x` `HLT` instruction can be `0` or `1`, choice is `1` for this program,
- `HLT` instruction can also be coded as `0b11111111`, it is not emitted by the program,
- bits 3 to 5 of the `JMP`, `CAL` and `RET` instructions can be anything, choice are `0`s for this program.

These choices can be changed in the `emit_halt`, `emit_jump`, `emit_call` and `emit_return` functions.
