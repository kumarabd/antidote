//! Step 6: Ignore filters - drop noisy paths before processing.

/// Hard ignore directory segments (if path contains these, drop the event).
pub const IGNORE_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    ".next",
    ".venv",
    "venv",
    "__pycache__",
    ".DS_Store",
];

/// Hard ignore file suffixes.
pub const IGNORE_SUFFIXES: &[&str] = &[
    ".log",
    ".tmp",
    ".swp",
    ".lock",
    "monitor.db",         // SQLite databases (including daemon's own monitor.db)
    "monitor.db-journal",    // SQLite WAL journal (daemon writes to monitor.db-journal)
];

/// Tool churn paths (editor config dirs - ignore for v1 to reduce noise).
pub const IGNORE_TOOL_PATHS: &[&str] = &[
    ".cursor",
    ".vscode",
    ".idea",
];

/// Check if a path should be ignored (dropped).
pub fn should_ignore_path(path: &str) -> bool {
    let path_lower = path.to_lowercase();

    for dir in IGNORE_DIRS {
        if *dir == ".DS_Store" {
            if path_lower.ends_with(".ds_store") || path_lower.contains("/.ds_store") {
                return true;
            }
        } else if path_lower.contains(&format!("/{}/", dir))
            || path_lower.contains(&format!("\\{}\\", dir))
            || path_lower.ends_with(&format!("/{}", dir))
            || path_lower.ends_with(&format!("\\{}", dir))
        {
            return true;
        }
    }

    for suffix in IGNORE_SUFFIXES {
        if path_lower.ends_with(suffix) {
            return true;
        }
    }

    for tool in IGNORE_TOOL_PATHS {
        if path_lower.contains(&format!("/{}/", tool))
            || path_lower.contains(&format!("\\{}\\", tool))
            || path_lower.ends_with(&format!("/{}", tool))
        {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_under_node_modules_dropped() {
        assert!(should_ignore_path("/Users/me/proj/node_modules/foo/bar.js"));
        assert!(should_ignore_path("/proj/node_modules/whatever"));
    }

    #[test]
    fn git_changes_dropped() {
        assert!(should_ignore_path("/Users/me/repo/.git/HEAD"));
        assert!(should_ignore_path("/repo/.git/config"));
    }

    #[test]
    fn target_dropped() {
        assert!(should_ignore_path("/Users/me/rust/target/debug/main"));
    }

    #[test]
    fn vscode_cursor_idea_dropped() {
        assert!(should_ignore_path("/Users/me/proj/.vscode/settings.json"));
        assert!(should_ignore_path("/proj/.cursor/state"));
        assert!(should_ignore_path("/proj/.idea/workspace.xml"));
    }

    #[test]
    fn normal_path_not_dropped() {
        assert!(!should_ignore_path("/Users/me/proj/src/main.rs"));
        assert!(!should_ignore_path("/proj/package.json"));
    }

    #[test]
    fn daemon_db_files_dropped() {
        // Daemon's own SQLite files - should not be attributed to app sessions
        assert!(should_ignore_path("/Users/me/antidote/monitor.db"));
        assert!(should_ignore_path("/Users/me/antidote/monitor.db-journal"));
        assert!(should_ignore_path("/path/to/project/foo.db"));
    }
}
