# 1. Autonomous Rust Dumper with Conservative Field Optionality

We use an autonomous native Rust tool (`dumper_rust`) using MSVC RTTI parsing and `iced-x86` instruction decoding as the primary source of truth for protocol schema extraction, instead of depending on proprietary disassemblers (IDA Pro Hex-Rays / Binary Ninja). For field validation semantics, fields default to `required: false` unless an explicit runtime registration flag (`1 = required`) is proven in assembly, ensuring generated clients are resilient to server-side schema evolution.

## Context

The project previously relied on IDA Pro Hex-Rays scripts and Binary Ninja IL analyzers to dump `core.dll`. IDA required expensive commercial licenses with decompiler plugins, while Binary Ninja took minutes and had truncated type strings. Neither provided a repeatable, sub-second CLI pipeline. Furthermore, strict `required: true` markings on fields caused generated SDK clients to crash or reject valid server payloads during minor protocol updates.

## Decision

1. **Autonomous Tooling**: Build and maintain `dumper_rust` in Rust using `goblin` (PE headers), `msvc-demangler` + custom RTTI traversal (inheritance and vtables), and `iced-x86` (disassembly), running complete extraction in under 400 ms.
2. **Schema Invariants**: Combine IDA's precision in structural boundaries (rejecting dispatchers/converters) with Binja's clean decomposed type signatures (`int32_t`, `int64_t`, `char`, clean template arguments).
3. **Conservative Optionality**: In generated models, treat fields as `required: false` by default unless explicitly asserted by runtime flags, matching real-world protocol resilience.
4. **Single Canonical Dump Format**: Standardize exclusively on the rich decomposed type schema for downstream client SDK codegen, eliminating legacy IDA Pro schema formatting from `dumper_rust`.
