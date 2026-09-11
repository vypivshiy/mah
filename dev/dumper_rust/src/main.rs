use anyhow::{Context, Result};
use clap::Parser;
use dumper_rust::dumper::{Dumper, DumperOptions};
use dumper_rust::pe::PeImage;
use dumper_rust::rtti::RttiEngine;
use dumper_rust::scanner::ProtocolScanner;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(
    name = "dumper_rust",
    author = "mah project",
    version = "0.1.0",
    about = "Autonomous MSVC C++ x64 DLL Protocol & Model Dumper in Rust without disassemblers"
)]
struct Args {
    /// Path to core.dll binary
    #[arg(short, long, default_value = "dev/CM_FP_Unspecified.core.dll")]
    input: PathBuf,

    /// Output JSON file path
    #[arg(short, long, default_value = "dev/packets_rust.json")]
    output: PathBuf,

    /// Manual app_version override (auto-detected from binary if omitted)
    #[arg(long, default_value = "")]
    app_version: String,

    /// Manual build_number override (auto-detected from binary if omitted)
    #[arg(long, default_value_t = 0)]
    build_number: u32,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("=== Autonomous Rust Protocol Dumper ===");
    println!("Target binary: {:?}", args.input);

    let t_total = Instant::now();

    let bytes = fs::read(&args.input)
        .with_context(|| format!("Failed to read DLL file at {:?}", args.input))?;
    println!("Loaded {:.2} MB into memory", bytes.len() as f64 / 1_048_576.0);

    let t_pe = Instant::now();
    let pe = PeImage::parse(&bytes).context("Failed to parse PE headers")?;
    println!("Phase 1: PE parsed (image_base: 0x{:x}, {} sections, {} .pdata funcs) in {:?}",
        pe.image_base, pe.sections.len(), pe.pdata.len(), t_pe.elapsed()
    );

    let t_rtti = Instant::now();
    let rtti = RttiEngine::build(&pe).context("Failed to build RTTI engine")?;
    println!("Phase 2: RTTI indexed ({} types, {} vtables, {} smember vtables) in {:?}",
        rtti.type_descriptors.len(), rtti.vtable_to_type.len(), rtti.smember_vtables.len(), t_rtti.elapsed()
    );

    let t_scan = Instant::now();
    let scanner = ProtocolScanner::scan(&pe, &rtti).context("Failed to scan protocol entities")?;
    println!("Phase 3: Protocol scanned ({} packets, {} events, {} enums) in {:?}",
        scanner.packets.len(), scanner.events.len(), scanner.string_enums.len(), t_scan.elapsed()
    );

    let options = DumperOptions {
        version: dumper_rust::dumper::AppVersion {
            version: args.app_version,
            build: args.build_number,
        },
    };

    let t_dump = Instant::now();
    let result = Dumper::dump(&pe, &rtti, &scanner, &options).context("Failed to dump protocol models")?;
    println!("Phase 4: Full dump & BFS resolved in {:?}", t_dump.elapsed());

    let json_bytes = serde_json::to_vec_pretty(&result).context("Failed to serialize JSON")?;
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&args.output, &json_bytes)
        .with_context(|| format!("Failed to write dump JSON to {:?}", args.output))?;

    println!("Output written to: {:?}", args.output);
    println!("Version: {} (build {})", result.options.version, result.options.build);
    println!("Done! Total elapsed time: {:.2?}", t_total.elapsed());

    Ok(())
}
