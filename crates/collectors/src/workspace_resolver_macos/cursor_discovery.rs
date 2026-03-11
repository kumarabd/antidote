//! Cursor-specific root discovery. Independent of sessions.
//! Strategy: read storage.json for active windows → workspace.json per window for roots.
//! Other tools (VSCode, Claude) can have separate discovery modules with different strategies.

use super::{extract_paths_from_json, FileReader};
use serde_json::Value;
use std::path::Path;

fn cursor_base_path() -> Option<String> {
    let home_os = std::env::var_os("HOME")?;
    let home = home_os.to_string_lossy();
    if home.is_empty() {
        return None;
    }
    Some(format!("{}/Library/Application Support/Cursor", home))
}

fn cursor_storage_json_path() -> Option<String> {
    let base = cursor_base_path()?;
    for sub in ["User/storage.json", "User/globalStorage/storage.json"] {
        let p = format!("{}/{}", base, sub);
        if std::path::Path::new(&p).exists() {
            return Some(p);
        }
    }
    None
}

fn cursor_workspace_storage_path() -> Option<String> {
    let base = cursor_base_path()?;
    let p = format!("{}/User/workspaceStorage", base);
    if std::path::Path::new(&p).exists() {
        Some(p)
    } else {
        None
    }
}

fn file_uri_to_path(uri: &str) -> Option<String> {
    let s = uri
        .strip_prefix("file://")?
        .replace("%20", " ")
        .replace("%2F", "/");
    let path = if s.starts_with("//") {
        s[1..].to_string()
    } else if s.starts_with('/') {
        s
    } else if s.starts_with("~/") {
        let home = std::env::var_os("HOME")?;
        format!("{}/{}", home.to_string_lossy(), s.trim_start_matches("~/"))
    } else {
        return None;
    };
    if path.is_empty() {
        return None;
    }
    Some(path)
}

fn normalize_path_for_match(p: &str) -> String {
    let expanded = if p.starts_with("~/") {
        std::env::var_os("HOME")
            .map(|h| format!("{}/{}", h.to_string_lossy(), p.trim_start_matches("~/")))
            .unwrap_or_else(|| p.to_string())
    } else {
        p.to_string()
    };
    Path::new(&expanded)
        .canonicalize()
        .map(|x| x.to_string_lossy().to_string())
        .unwrap_or(expanded)
}

fn opened_folder_paths_from_storage(storage_json: &str) -> Vec<String> {
    let v: Value = match serde_json::from_str(storage_json) {
        Ok(x) => x,
        Err(_) => return vec![],
    };
    let mut out = Vec::new();
    let obj = match v.as_object() {
        Some(o) => o,
        None => return vec![],
    };

    // windowsState.openedWindows (Cursor format)
    if let Some(ws) = obj.get("windowsState").and_then(|o| o.get("openedWindows")).and_then(Value::as_array) {
        for win in ws {
            if let Some(uri) = win.get("folder").and_then(Value::as_str) {
                if let Some(path) = file_uri_to_path(uri) {
                    if Path::new(&path).exists() {
                        out.push(normalize_path_for_match(&path));
                    }
                }
            }
            if let Some(ident) = win.get("workspaceIdentifier") {
                if let Some(uri) = ident.get("configURIPath").and_then(Value::as_str) {
                    if let Some(ws_path) = file_uri_to_path(uri) {
                        if let Ok(json_str) = std::fs::read_to_string(&ws_path) {
                            for p in extract_paths_from_json(&json_str) {
                                if Path::new(&p).exists() {
                                    out.push(normalize_path_for_match(&p));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // lastActiveWindow.folder
    if let Some(folder) = obj.get("windowsState").and_then(|o| o.get("lastActiveWindow")).and_then(|w| w.get("folder")).and_then(Value::as_str) {
        if let Some(path) = file_uri_to_path(folder) {
            if Path::new(&path).exists() {
                out.push(normalize_path_for_match(&path));
            }
        }
    }

    for key in ["opener.openedPathsList", "openerOpenedPathsList", "openerOpenedPathsList:org.cursor.workspaceData"] {
        let list = match obj.get(key) {
            Some(l) => l,
            None => continue,
        };
        for arr_key in ["workspaces3", "entries"] {
            if let Some(arr) = list.get(arr_key).and_then(Value::as_array) {
                for entry in arr {
                    if let Some(uri) = entry.get("folderUri").or(entry.get("folder")).and_then(Value::as_str) {
                        if let Some(path) = file_uri_to_path(uri) {
                            if Path::new(&path).exists() {
                                out.push(normalize_path_for_match(&path));
                            }
                        } else if Path::new(uri).exists() {
                            out.push(normalize_path_for_match(uri));
                        }
                    }
                    if let Some(path) = entry.get("folder").and_then(Value::as_str) {
                        if Path::new(path).exists() {
                            out.push(normalize_path_for_match(path));
                        }
                    }
                }
            }
        }
        if let Some(arr) = list.get("folders").and_then(Value::as_array) {
            for entry in arr {
                if let Some(uri) = entry.as_str() {
                    if let Some(path) = file_uri_to_path(uri) {
                        if Path::new(&path).exists() {
                            out.push(normalize_path_for_match(&path));
                        }
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// One discovered Cursor window: source_id and roots.
#[derive(Debug, Clone)]
pub struct CursorWindow {
    pub source_id: String,
    pub roots: Vec<String>,
}

/// Discover all active Cursor windows and their roots from storage.
pub fn discover_cursor_roots<F: FileReader>(reader: &F) -> Vec<CursorWindow> {
    let Some(storage_path) = cursor_storage_json_path() else {
        return vec![];
    };
    let Some(storage_json) = reader.read_file(&storage_path) else {
        return vec![];
    };
    let opened_paths = opened_folder_paths_from_storage(&storage_json);
    if opened_paths.is_empty() {
        return vec![];
    }
    let opened_set: std::collections::HashSet<_> = opened_paths.iter().map(|s| s.as_str()).collect();

    let Some(ws_base) = cursor_workspace_storage_path() else {
        return vec![];
    };
    let Ok(entries) = std::fs::read_dir(&ws_base) else {
        return vec![];
    };

    let mut windows = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().to_string();
        let workspace_json_path = dir.join("workspace.json");
        let workspace_json_path_str = workspace_json_path.to_string_lossy();
        let Some(json_str) = reader.read_file(&workspace_json_path_str) else {
            continue;
        };
        let roots = extract_paths_from_json(&json_str);
        if roots.is_empty() {
            continue;
        }
        let is_active = roots.iter().any(|r| {
            let norm = normalize_path_for_match(r);
            opened_set.contains(norm.as_str())
        });
        if !is_active {
            continue;
        }
        windows.push(CursorWindow {
            source_id: format!("cursor:ws:{}", id),
            roots,
        });
    }
    windows
}
