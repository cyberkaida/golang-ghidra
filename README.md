# Golang Ghidra

This extension implements the Golang calling convention and
auto analysis modules for Golang binaries.

It currently supports:
- Extraction of static Go strings
- Parsing of various Go compiler structures
  - pclntab, fntab, etc
- Function identification using the function table

These components significantly improve Golang decompilation
and analysis in Ghidra. Hundreds of methods are identified
over the built in function identification.

This module is still under heavy development. It currently
supports analysis of Golang 1.19.3 for Apple Silicon, aarch64 and x86_64,
support for other compiler versions and architectures are planned
but currently unimplemented.

Support is available for macOS, Linux and Windows binaries.

## Under development

Additional analysis modules are under development:
- Golang type extraction
- Assigning correct signatures to methods using Go debug information
- Multiple return values
- Splitting Go runtime methods from user defined modules in the UI

## Installation

Prebuilt binaries are available from the releases page or from the GitHub action CI.

The extension can be installed through Ghidra. Open Ghidra,
open the File menu in the project view and click "Install Extensions...".
Click the green plus icon, then select the built extension zip from the `dist/`
directory.

## Building

To install the extension you will need to install `gradle` for your platform.

```sh
export GHIDRA_INSTALL_DIR=<path to your Ghidra installation>
gradle
```

Once the extension is built it will be available in `dist/`.

GitHub actions are configure to build for recent versions of Ghidra.

## Development

This extension is under heavy development. There will be bugs and edge cases.
Please report issues here on GitHub.

I am streaming development of [Golang Ghidra on Twitch!](https://twitch.tv/cyberkaida)
Follow there for development updates!
