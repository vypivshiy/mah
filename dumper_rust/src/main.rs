use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use dumper_rust::compact::format_compact_dump_with_options;
use dumper_rust::datamining::{
    discover_config_dll, emit_config_json, emit_metadata_json, extract_config_from_file,
    DataminingCoordinator,
};
use dumper_rust::dumper::{Dumper, DumperOptions};
use dumper_rust::pe::PeImage;
use dumper_rust::rtti::RttiEngine;
use dumper_rust::scanner::ProtocolScanner;
use dumper_rust::unpacker::UnpackArgs;
use dumper_rust::updater::UpdateArgs;
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
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Check for desktop client updates and download MAX.msi installer
    Update(UpdateArgs),

    /// Unpack MAX.msi and selectively extract core.dll and config.dll
    Unpack(UnpackArgs),

    /// Dump protocol packets, models, enums, features, and metadata from core.dll
    Dump(DumpArgs),
}

#[derive(clap::Args, Debug, Clone)]
pub struct DumpArgs {
    /// Positional path to target MSVC C++ x64 core DLL binary (defaults to CM_FP_Unspecified.core.dll)
    #[arg(value_name = "TARGET")]
    pub target: Option<PathBuf>,

    /// Output JSON schema file path
    #[arg(short, long, default_value = "packets_rust.json")]
    pub output: PathBuf,

    /// Optional explicit path to config DLL
    #[arg(long, value_name = "CONFIG_PATH")]
    pub config: Option<PathBuf>,

    /// Output metadata JSON snapshot file path
    #[arg(long, default_value = "metadata.json", value_name = "PATH")]
    pub metadata_output: PathBuf,

    /// Output standalone config JSON file path
    #[arg(long, default_value = "config.json", value_name = "PATH")]
    pub config_output: PathBuf,

    /// Include memory RVA offsets in metadata.json and compact output
    #[arg(long, default_value_t = false)]
    pub with_rva: bool,

    /// Suppress metadata.json generation
    #[arg(long, default_value_t = false)]
    pub no_metadata: bool,

    /// Optional diagnostics JSON sidecar output path
    #[arg(long)]
    pub diagnostics_output: Option<PathBuf>,

    /// Optional compact plain-text output file path
    #[arg(
        short = 'c',
        long,
        num_args = 0..=1,
        default_missing_value = "packets_rust.compact.txt"
    )]
    pub compact_output: Option<PathBuf>,

    /// Manual app_version override (auto-detected from binary if omitted)
    #[arg(long, default_value = "")]
    pub app_version: String,

    /// Manual build_number override (auto-detected from binary if omitted)
    #[arg(long, default_value_t = 0)]
    pub build_number: u32,
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create parent directory {:?}", parent))?;
    }
    Ok(())
}

fn run_dump(args: DumpArgs) -> Result<()> {
    let default_name = "CM_FP_Unspecified.core.dll";
    let input_path = match args.target {
        Some(ref path) => {
            if !path.exists() {
                anyhow::bail!("Target binary not found: {:?}", path);
            }
            path.clone()
        }
        None => {
            let default_path = PathBuf::from(default_name);
            if default_path.exists() {
                default_path
            } else {
                anyhow::bail!("'CM_FP_Unspecified.core.dll' not found in current directory. Run 'dumper_rust unpack' first or specify target: 'dumper_rust dump <path.dll>'");
            }
        }
    };

    println!("=== Autonomous Rust Protocol Dumper ===");
    println!("Target binary: {:?}", input_path);

    let t_total = Instant::now();

    // 1. Config discovery & extraction
    let config_dll_path = discover_config_dll(&input_path, args.config.as_deref());
    let mut config_val = None;
    if let Some(cfg_path) = config_dll_path {
        println!("Config DLL discovered: {:?}", cfg_path);
        match extract_config_from_file(&cfg_path) {
            Ok(cfg) => {
                if let Err(e) = emit_config_json(&cfg, &args.config_output) {
                    eprintln!("Warning: Failed to write config.json: {:#}", e);
                } else {
                    println!("Config written to: {:?}", args.config_output);
                }
                config_val = Some(cfg);
            }
            Err(e) => {
                eprintln!(
                    "Warning: Failed to extract config from {:?}: {:#}",
                    cfg_path, e
                );
            }
        }
    } else if let Some(ref explicit) = args.config {
        anyhow::bail!("Specified config path does not exist: {:?}", explicit);
    }

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

    let detected_proto_ver = config_val
        .as_ref()
        .and_then(|c| c.get("api_version_uint"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);

    let options = DumperOptions {
        version: dumper_rust::dumper::AppVersion {
            version: args.app_version,
            build: args.build_number,
            protocol_version: detected_proto_ver,
        },
        config: config_val.clone(),
        protocol_version: detected_proto_ver,
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
    println!("Output written to: {:?}", args.output);

    if !args.no_metadata {
        let t_meta = Instant::now();
        let snapshot = DataminingCoordinator::build(
            &pe,
            &rtti,
            &scanner,
            &result.dump,
            config_val.as_ref(),
            args.with_rva,
        )
        .context("Failed to build metadata snapshot")?;
        println!("Phase 5: Metadata snapshot built in {:?}", t_meta.elapsed());

        emit_metadata_json(&snapshot, &args.metadata_output).with_context(|| {
            format!("Failed to write metadata JSON to {:?}", args.metadata_output)
        })?;
        println!("Metadata written to: {:?}", args.metadata_output);
    }

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
        let compact_dump = format_compact_dump_with_options(&result.dump, args.with_rva);
        fs::write(compact_output, compact_dump)
            .with_context(|| format!("Failed to write compact dump to {:?}", compact_output))?;
        println!("Compact output written to: {:?}", compact_output);
    }

    println!(
        "Version: {} (build {})",
        result.dump.options.version, result.dump.options.build
    );
    println!("Done! Total elapsed time: {:.2?}", t_total.elapsed());

    Ok(())
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Update(update_args)) => {
            let code = dumper_rust::updater::run(&update_args);
            std::process::exit(code);
        }
        Some(Commands::Unpack(unpack_args)) => {
            if let Err(err) = dumper_rust::unpacker::run_unpack(&unpack_args) {
                eprintln!("Error: {err}");
                std::process::exit(1);
            }
        }
        Some(Commands::Dump(dump_args)) => {
            if let Err(err) = run_dump(dump_args) {
                eprintln!("Error: {err:#}");
                std::process::exit(1);
            }
        }
        None => {
            if let Err(err) = Cli::command().print_help() {
                eprintln!("Error: {err}");
                std::process::exit(1);
            }
            println!();
        }
    }
}
