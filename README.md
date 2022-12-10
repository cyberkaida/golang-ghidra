# Golang Ghidra

This extension implements the Golang calling convention and
an auto analysis for Golang string extraction.

These two components significantly improve Golang decompilation
and analysis in Ghidra.

This module is still under heavy development. It currently
supports Golang 1.19.3 for Apple Silicon, support for other
compiler versions and architectures are planned, but currently
unimplemented.

## Building

To install the extension you will need to install `gradle` for your platform.

```sh
export GHIDRA_INSTALL_DIR=<path to your Ghidra installation>
gradle
```

Once the extension is built it will be available in `dist/`.

## Installation

You will need to build the extension from source. Once the extension
is stable I will provide prebuilt binaries.

The extension can be installed through Ghidra. Open Ghidra,
open the File menu in the project view and click "Install Extensions...".
Click the green plus icon, then select the built extension zip from the `dist/`
directory.

## Development

This extension is under heavy development. There will be bugs and edge cases.

I am streaming development of [Golang Ghidra on Twitch!](https://twitch.tv/cyberkaida)
Follow there for development updates!
