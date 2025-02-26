# x86 PE executable

A little experiment with writing x86 32-bit machine code to an executable directly with the [Portable Executable (PE)](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) file format and no dependencies.

The inspiration of this project came from [gingerbill/blaise](https://github.com/gingerBill/blaise), a super simple Pascal-like language that has backend that generates x86 32-bit machine code. This program is basically just the PE-writer from blaise without the rest of the compiler.

## Usage

Compile:
```bash
$ clang src/main.c -Isrc -o make_pe.exe
```

Run:
```bash
$ ./make_pe.exe # run the driver program
$ ./result.exe # run the output
```

And `result.exe` should just exit with the code `69`.


