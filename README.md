# ghidra_nodejs

## Description

GHIDRA plugin to parse, disassemble and decompile NodeJS Bytenode (JSC) binaries.

## Supported NodeJS versions:
- v8.16.0 (x64) (V8 version: 6.2.414.77)
- v8.16.0 (x86) (V8 version: 6.2.414.77)

## Build instructions

1.  Clone the repo
2.  Import the repo into Eclipse with GhidraDev plugin installed
3.  Link Ghidra to your Ghidra's installation (option in the project's context menu)
4.  Export & build plugin using the project's context menu. Eclipse will generate a resulting .zip archive with the plugin.
5.  In Ghidra: File->Install Extensions...->Press green (Plus/+) button, then select previously generated .zip archive to install it. Press OK, then Restart Ghidra.
6.  Drag-n-drop jsc files.
