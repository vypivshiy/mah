pub mod compact;
pub mod datamining;
pub mod discriminator;
pub mod dumper;
pub mod extractor;
pub mod model_resolver;
pub(crate) mod msvc;
pub mod pe;
pub mod rtti;
pub mod scanner;
pub mod type_parser;
pub mod unpacker;

pub use datamining::coordinator::{
    build_metadata_snapshot, emit_metadata_json, format_metadata_json, DataminingCoordinator,
    MetadataMeta, MetadataPacketEntry, MetadataSnapshot, MetadataSummary,
};
pub use unpacker::{
    run_unpack, safe_join, unpack, unpack_from_package, ExtractedFile, FileFilter, UnpackArgs,
    UnpackError, UnpackResult,
};

