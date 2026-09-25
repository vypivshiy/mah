# 1. Autonomous Rust Dumper with Conservative Field Optionality

We maintain an autonomous native Rust tool (`dumper_rust`) using MSVC RTTI parsing and `iced-x86` instruction decoding as a WIP/PoC protocol schema extraction path. External SDK codegen should continue to use the Binary Ninja dump until the Rust dumper is explicitly promoted. For field validation semantics, fields default to `required: false` unless an explicit runtime registration flag (`1 = required`) is proven in assembly, ensuring generated clients are resilient to server-side schema evolution.

## Context

The project previously relied on IDA Pro Hex-Rays scripts and Binary Ninja IL analyzers to dump `core.dll`. IDA required expensive commercial licenses with decompiler plugins, while Binary Ninja took minutes and had truncated type strings. Neither provided a repeatable standalone CLI pipeline. Furthermore, strict `required: true` markings on fields caused generated SDK clients to crash or reject valid server payloads during minor protocol updates.

## Decision

1. **Autonomous Tooling**: Build and maintain `dumper_rust` in Rust using `goblin` (PE headers), `msvc-demangler` + custom RTTI traversal (inheritance and vtables), and `iced-x86` (disassembly), running complete extraction within 20 seconds.
2. **Schema Invariants**: Combine IDA's precision in structural boundaries (rejecting dispatchers/converters) with Binja's clean decomposed type signatures (`int32_t`, `int64_t`, `char`, clean template arguments).
3. **Conservative Optionality**: In generated models, treat fields as `required: false` by default unless explicitly asserted by runtime flags, matching real-world protocol resilience.
4. **WIP Rust Dump Format**: Keep the Rust dump in the rich decomposed type schema for review and future codegen, while treating Binary Ninja output as the current external codegen source until Rust graduates from WIP.
