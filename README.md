# 🛡️ SDB: A Linux Debugger

A hobbyist debugger built from the ground up in Modern C++, following the architectural patterns outlined in Sy Brand's *"Building a Debugger"* series and book. This project explores the low-level mechanics of the Linux `ptrace` system call, DWARF debug information, and breakpoint injection.

## 🚀 Features

* **Process Launching:** Start a tracee process and attach to it immediately.
* **Breakpoint Management:**
    * Software breakpoints using `int 3` instruction injection.
    * Automatic instruction restoration on continue.
* **Register Manipulation:** Read and write to CPU registers (e.g., `rax`, `rip`).
* **Memory Inspection:** Examine and modify the tracee's memory space.
* **Execution Control:** Continue execution and single-step through instructions.

---

## 🏗️ Architecture

The debugger operates by leveraging the **Linux ptrace API**, acting as the "tracer" to control the execution of a "tracee."



* **Debugger Class:** The core engine managing the REPL (Read-Eval-Print Loop) and the tracee PID.
* **Breakpoint Class:** Handles the "theft" of the original byte at an address to replace it with `0xcc`.
* **Register Interface:** A wrapper around `user_regs_struct` for easy access to x86_64 state.

---

## 🛠️ Getting Started

### Prerequisites

* A Linux environment (x86_64)
* `g++` or `clang` with C++17 support or higher
* `libelfin` (for DWARF/ELF parsing)
* More TBD

### Installation

```bash
git clone https://github.com/ultrakapy/sdb.git
cd sdb
mkdir build && cd build
cmake ..
make