use std::path::PathBuf;

#[allow(dead_code)]
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

#[allow(dead_code)]
pub fn resolve_core_dll() -> Option<PathBuf> {
    if let Some(path) = resolve_env_path("CORE_DLL_PATH") {
        if path.exists() {
            return Some(path);
        }
    }
    let direct = PathBuf::from(r"D:\PycharmProjects\mah\CM_FP_Unspecified.core.dll");
    if direct.exists() {
        return Some(direct);
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(parent) = manifest_dir.parent() {
        let candidate = parent.join("CM_FP_Unspecified.core.dll");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

#[allow(dead_code)]
pub fn resolve_config_dll() -> Option<PathBuf> {
    if let Some(path) = resolve_env_path("CONFIG_DLL_PATH") {
        if path.exists() {
            return Some(path);
        }
    }
    let direct = PathBuf::from(r"D:\PycharmProjects\mah\CM_FP_Unspecified.config.dll");
    if direct.exists() {
        return Some(direct);
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(parent) = manifest_dir.parent() {
        let candidate = parent.join("CM_FP_Unspecified.config.dll");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}
