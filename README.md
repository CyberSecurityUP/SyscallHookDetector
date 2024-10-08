# SyscallHookDetector

**SyscallHookDetector** is a C++ tool designed to detect hooked syscalls in the `ntdll.dll` library on Windows systems. This tool scans exported syscalls in `ntdll.dll` and checks for potential hooks or modifications by analyzing the function's prologue and common redirection instructions like `jmp` and `call`.

## Features

- Detects hooked or modified syscalls (e.g., `Nt` or `Zw` functions).
- Compares the function's prologue with the standard syscall stub.
- Flags potential hooks using common indicators like `jmp` and `call` instructions.
- Simple and efficient approach to syscall hook detection.

## How It Works

The tool scans through the exported syscalls in `ntdll.dll` and checks the first few bytes of each function to determine whether it has been altered. A typical syscall prologue starts with:

```assembly
4c 8b d1 b8
```

If the prologue does not match or if a redirection (`jmp` or `call`) is detected, the tool flags the function as hooked or potentially modified.

## Usage

1. Clone the repository:

```bash
git clone https://github.com/CuberSecurityUP/SyscallHookDetector.git
```

2. Open the project in your preferred C++ development environment.

3. Compile and run the program on a Windows system.

4. The tool will output a list of syscalls and indicate whether each function is hooked or not.

## Example Output

```plaintext
Not hooked: NtCreateFile : 0x7ffb31a3b210
Hooked or modified: NtOpenProcess : 0x7ffb31a3b360
```

## Requirements

- Windows operating system
- C++ Compiler (MSVC, MinGW, etc.)
- `Windows.h` for accessing Windows APIs

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

---

## Contribution

Contributions are welcome! Feel free to submit issues or pull requests for new features or bug fixes.

---

## Disclaimer

This tool is for educational and research purposes only. Use it responsibly and in compliance with local laws.

---

### Author

- Joas Antonio dos Santos

---

### References

- https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions
- https://github.com/Helixo32/SimpleEDR
- https://github.com/Mr-Un1k0d3r/EDRs
