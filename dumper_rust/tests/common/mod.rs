use std::path::PathBuf;

pub fn resolve_env_path(var_name: &str) -> Option<PathBuf> {
    let raw = match std::env::var(var_name) {
        Ok(val) if !val.trim().is_empty() => val,
        _ => return None,
    };
    let path = PathBuf::from(raw);
    if path.exists() {
        Some(path)
    } else {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        if let Some(parent) = manifest_dir.parent() {
            let root_relative = parent.join(&path);
            if root_relative.exists() {
                return Some(root_relative);
            }
        }
        Some(path)
    }
}
