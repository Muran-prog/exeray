# ExeRay

[![CI](https://github.com/Muran-prog/ExeRay/actions/workflows/ci.yml/badge.svg)](https://github.com/Muran-prog/ExeRay/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.85+-orange.svg)](https://www.rust-lang.org/)
[![C++](https://img.shields.io/badge/C++-20-blue.svg)](https://isocpp.org/)
[![Status](https://img.shields.io/badge/Status-In_Development-yellow.svg)]()

High-performance console application with Rust UI and C++ computational backend. Zero-copy FFI, lock-free concurrency, minimal memory footprint.

---

## Table of Contents

- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Building](#building)
- [Usage](#usage)
- [FFI Design](#ffi-design)
- [Performance](#performance)
- [License](#license)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Single Binary                          │
├─────────────────────────────────────────────────────────────┤
│  Rust (Ratatui)              │  C++ Core                    │
│  ─────────────────           │  ──────────                  │
│  Terminal UI                 │  Arena Allocator             │
│  Event Loop                  │  Thread Pool                 │
│  ViewState Assembly          │  Computation Engine          │
│                              │  Atomic State                │
├──────────────────────────────┴──────────────────────────────┤
│                     cxx Bridge (FFI)                        │
│         Type-safe bindings, no serialization overhead       │
└─────────────────────────────────────────────────────────────┘
```

### Design Principles

| Principle | Implementation |
|-----------|----------------|
| Zero-copy | Raw pointer views with lifetime guarantees |
| Lock-free | Atomic flags for status, SPSC queues for data |
| Cache-friendly | 64-byte aligned arena allocator |
| Single binary | Static linking with LTO |

---

## Project Structure

```
ExeRay/
├── Cargo.toml                    # Workspace configuration
├── CMakeLists.txt                # Root CMake
├── core/                         # C++ computational engine
│   ├── CMakeLists.txt
│   ├── include/exeray/
│   │   ├── types.hpp             # Status flags
│   │   ├── arena.hpp             # Cache-aligned allocator
│   │   ├── thread_pool.hpp       # Worker threads
│   │   ├── engine.hpp            # Core computation
│   │   └── ffi.hpp               # FFI handle
│   └── src/
│       └── stub.cpp
├── crates/
│   ├── exeray-ffi/               # Rust-C++ bridge
│   │   ├── Cargo.toml
│   │   ├── build.rs              # CMake + cxx integration
│   │   └── src/
│   │       └── lib.rs            # cxx::bridge definitions
│   └── exeray/                   # Terminal UI
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs           # Entry point
│           ├── app.rs            # Application state
│           └── ui.rs             # Ratatui widgets
└── .github/
    └── workflows/
        └── ci.yml                # Cross-platform CI
```

---

## Requirements

### Build Dependencies

| Dependency | Version | Notes |
|------------|---------|-------|
| Rust | 1.85+ | Edition 2024 |
| CMake | 3.20+ | For C++ core |
| C++ Compiler | GCC 11+ / Clang 14+ / MSVC 2022 | C++20 support |

### Platforms

| Platform | Status |
|----------|--------|
| Linux (x86_64) | Supported |
| macOS (x86_64, ARM64) | Supported |
| Windows (x86_64) | Supported |

---

## Building

### Debug Build

```bash
cargo build
```

### Release Build

```bash
cargo build --release
```

The release build enables:
- LTO (Link-Time Optimization)
- Single codegen unit
- Panic abort
- Symbol stripping

### Verify Build

```bash
cargo clippy -- -D warnings
cargo test
```

---

## Usage

### Running

```bash
./target/release/exeray
```

### Controls

| Key | Action |
|-----|--------|
| `Space` | Start computation task |
| `Q` / `Esc` | Quit |

### UI Layout

```
┌─Engine──────────────────────────────────────────┐
│ ExeRay │ Gen: 0 │ Threads: 8                    │
└─────────────────────────────────────────────────┘
┌─Progress────────────────────────────────────────┐
│ ████████████████████░░░░░░░░░░░░░░░░░░░░░ 50%   │
└─────────────────────────────────────────────────┘
┌─Status──────────────────────────────────────────┐
│ Running                                         │
└─────────────────────────────────────────────────┘
Space: Start │ Q: Quit
```

---

## FFI Design

### Bridge Pattern

The FFI layer uses [cxx](https://cxx.rs/) for type-safe bindings between Rust and C++.

```rust
#[cxx::bridge(namespace = "exeray")]
mod ffi {
    unsafe extern "C++" {
        type Handle;

        fn create(arena_mb: usize, threads: usize) -> UniquePtr<Handle>;
        fn submit(self: Pin<&mut Handle>);
        fn generation(self: &Handle) -> u64;
        fn flags(self: &Handle) -> u64;
        fn progress(self: &Handle) -> f32;
    }
}
```

### Type Ownership

| Type | Owner | Access Pattern |
|------|-------|----------------|
| `Handle` | Rust (UniquePtr) | Exclusive |
| `Engine` | C++ | Via Handle |
| `Arena` | C++ | Internal |
| `ViewState` | Rust | Assembled from accessors |

### Memory Model

- C++ allocates all computational buffers via arena
- Rust receives primitive values (no pointer sharing for state)
- No serialization overhead (direct function calls)

---

## Performance

### Binary Size

| Build | Size |
|-------|------|
| Debug | ~15 MB |
| Release | ~648 KB |

### Compile-Time Optimizations

```toml
[profile.release]
lto = "fat"           # Cross-crate optimization
codegen-units = 1     # Better optimization
panic = "abort"       # Smaller binary
strip = true          # Remove symbols
```

### Runtime Characteristics

| Metric | Target |
|--------|--------|
| FFI call overhead | < 10 ns |
| State poll latency | < 1 μs |
| Memory allocations (hot path) | 0 |

---

## License

MIT License. See [LICENSE](LICENSE) for details.

Copyright (c) 2026 Muran-prog
