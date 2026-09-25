use anyhow::{Context, Result};
use clap::Parser;
use dumper_rust::compact::format_compact_dump;
use dumper_rust::dumper::{Dumper, DumperOptions};
use dumper_rust::pe::PeImage;
use dumper_rust::rtti::RttiEngine;
use dumper_rust::scanner::ProtocolScanner;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(
    name = "dumper_rust",
    author = "mah project",
    version = "0.1.0",
    about = "Autonomous MSVC C++ x64 DLL Protocol & Model Dumper in Rust without disassemblers"
)]
struct Args {
    /// Positional path to target MSVC C++ x64 core DLL binary
    #[arg(value_name = "TARGET")]
    target: PathBuf,

    /// Output JSON schema file path
    #[arg(short, long, default_value = "packets_rust.json")]
    output: PathBuf,

    /// Optional diagnostics JSON sidecar output path
    #[arg(long)]
    diagnostics_output: Option<PathBuf>,

    /// Optional compact plain-text output file path
    #[arg(
        short = 'c',
        long,
        num_args = 0..=1,
        default_missing_value = "packets_rust.compact.txt"
    )]
    compact_output: Option<PathBuf>,

    /// Manual app_version override (auto-detected from binary if omitted)
    #[arg(long, default_value = "")]
    app_version: String,

    /// Manual build_number override (auto-detected from binary if omitted)
    #[arg(long, default_value_t = 0)]
    build_number: u32,
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create parent directory {:?}", parent))?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let input_path = args.target;

    println!("=== Autonomous Rust Protocol Dumper ===");
    println!("Target binary: {:?}", input_path);

    let t_total = Instant::now();

    let bytes = fs::read(&input_path)
        .with_context(|| format!("Failed to read DLL file at {:?}", input_path))?;
    println!(
        "Loaded {:.2} MB into memory",
        bytes.len() as f64 / 1_048_576.0
    );

    let t_pe = Instant::now();
    let pe = PeImage::parse(&bytes).context("Failed to parse PE headers")?;
    println!(
        "Phase 1: PE parsed (image_base: 0x{:x}, {} sections, {} .pdata funcs) in {:?}",
        pe.image_base,
        pe.sections.len(),
        pe.pdata.len(),
        t_pe.elapsed()
    );

    let t_rtti = Instant::now();
    let rtti = RttiEngine::build(&pe).context("Failed to build RTTI engine")?;
    println!(
        "Phase 2: RTTI indexed ({} types, {} vtables, {} smember vtables) in {:?}",
        rtti.type_descriptors.len(),
        rtti.vtable_to_type.len(),
        rtti.smember_vtables.len(),
        t_rtti.elapsed()
    );

    let t_scan = Instant::now();
    let scanner = ProtocolScanner::scan(&pe, &rtti).context("Failed to scan protocol entities")?;
    println!(
        "Phase 3: Protocol scanned ({} packets, {} events, {} enums) in {:?}",
        scanner.packets.len(),
        scanner.events.len(),
        scanner.string_enums.len(),
        t_scan.elapsed()
    );

    let options = DumperOptions {
        version: dumper_rust::dumper::AppVersion {
            version: args.app_version,
            build: args.build_number,
        },
    };

    let t_dump = Instant::now();
    let result = Dumper::dump_with_diagnostics(&pe, &rtti, &scanner, &options)
        .context("Failed to dump protocol models")?;
    println!(
        "Phase 4: Full dump & BFS resolved in {:?}",
        t_dump.elapsed()
    );

    let json_bytes = serde_json::to_vec_pretty(&result.dump).context("Failed to serialize JSON")?;
    ensure_parent_dir(&args.output)?;
    fs::write(&args.output, &json_bytes)
        .with_context(|| format!("Failed to write dump JSON to {:?}", args.output))?;

    if let Some(path) = &args.diagnostics_output {
        ensure_parent_dir(path)?;
        let diagnostics_bytes = serde_json::to_vec_pretty(&result.diagnostics)
            .context("Failed to serialize diagnostics JSON")?;
        fs::write(path, &diagnostics_bytes)
            .with_context(|| format!("Failed to write diagnostics JSON to {path:?}"))?;
        println!("Diagnostics written to: {path:?}");
    }

    if let Some(compact_output) = &args.compact_output {
        ensure_parent_dir(compact_output)?;
        let compact_dump = format_compact_dump(&result.dump);
        fs::write(compact_output, compact_dump)
            .with_context(|| format!("Failed to write compact dump to {:?}", compact_output))?;
        println!("Compact output written to: {:?}", compact_output);
    }

    println!("Output written to: {:?}", args.output);
    println!(
        "Version: {} (build {})",
        result.dump.options.version, result.dump.options.build
    );
    println!("Done! Total elapsed time: {:.2?}", t_total.elapsed());

    Ok(())
}
