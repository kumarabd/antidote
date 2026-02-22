//! Step 6: Root sanity checks - prevent watching unsafe or too-broad roots.

use std::path::{Path, PathBuf};
use tracing::debug;

/// Decision after evaluating a candidate root.
#[derive(Debug, Clone)]
pub enum RootDecision {
    Accept {
        normalized_root: PathBuf,
        #[allow(dead_code)]
        reason: String,
    },
    Reject {
        reason: String,
    },
}

/// Project marker files that indicate a valid project root.
const PROJECT_MARKERS: &[&str] = &[
    ".git",
    "package.json",
    "go.mod",
    "Cargo.toml",
    "pyproject.toml",
    "requirements.txt",
    "pom.xml",
    "build.gradle",
    "Gemfile",
];

/// Paths that are too broad to watch (relative to home or absolute).
fn is_broad_reject_path(path: &Path, home: &str) -> bool {
    let s = path.to_string_lossy();
    let home_trimmed = home.trim_end_matches('/');
    if s == home_trimmed || s == home {
        return true;
    }
    let path_lower = s.to_lowercase();
    for suffix in [
        "/Documents",
        "/Desktop",
        "/Downloads",
        "/Library",
    ] {
        let broad = format!("{}{}", home_trimmed, suffix);
        if path_lower == broad.to_lowercase() || path_lower.starts_with(&format!("{}/", broad.to_lowercase())) {
            return true;
        }
    }
    if s == "/" || s == "/Users" {
        return true;
    }
    false
}

/// Minimum path components under /Users/<user> (e.g. /Users/me/code/proj = 2 components: code, proj).
/// Fewer than 2 = too shallow (e.g. /Users/me or /Users/me/code without project marker).
const MIN_DEPTH_UNDER_HOME: usize = 2;

fn path_depth_under_home(path: &Path, home: &str) -> Option<usize> {
    let s = path.to_string_lossy();
    let home_trimmed = home.trim_end_matches('/');
    let rest = s.strip_prefix(home_trimmed)?.strip_prefix('/')?;
    if rest.is_empty() {
        return Some(0);
    }
    Some(rest.split('/').filter(|p| !p.is_empty()).count())
}

fn has_project_marker(path: &Path) -> bool {
    for marker in PROJECT_MARKERS {
        if marker.starts_with('.') {
            if path.join(marker).exists() {
                return true;
            }
        } else if path.join(marker).exists() {
            return true;
        }
    }
    false
}

/// Walk up from `start` to find .git directory. Max steps to avoid escaping to home.
const MAX_PROMOTE_STEPS: usize = 10;

fn promote_to_git_root(start: &Path, home: &str) -> PathBuf {
    let home_path = Path::new(home);
    let mut current = start.to_path_buf();
    for _ in 0..MAX_PROMOTE_STEPS {
        if current.join(".git").exists() {
            return current;
        }
        if current.parent().map_or(true, |p| !p.starts_with(home_path) && p != Path::new("/")) {
            break;
        }
        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            break;
        }
    }
    start.to_path_buf()
}

/// Normalize path: expand ~, canonicalize, strip trailing slashes.
pub fn normalize_path(path: &str) -> Option<PathBuf> {
    let expanded = if path.starts_with("~/") {
        let home = std::env::var_os("HOME")?;
        let rest = path.strip_prefix("~/").unwrap_or(path);
        PathBuf::from(home).join(rest)
    } else if path == "~" {
        PathBuf::from(std::env::var_os("HOME")?)
    } else {
        PathBuf::from(path)
    };
    let canonical = expanded.canonicalize().ok().or_else(|| {
        if expanded.exists() {
            Some(expanded)
        } else {
            None
        }
    })?;
    let s = canonical.to_string_lossy().trim_end_matches('/').to_string();
    Some(PathBuf::from(s))
}

/// Evaluate a candidate root. Returns Accept or Reject with reason.
pub fn evaluate_root(path: &str) -> RootDecision {
    let home = match std::env::var_os("HOME") {
        Some(h) => h.to_string_lossy().to_string(),
        None => return RootDecision::Reject {
            reason: "HOME not set".to_string(),
        },
    };

    let normalized = match normalize_path(path) {
        Some(p) => p,
        None => {
            return RootDecision::Reject {
                reason: format!("Path does not exist or could not be normalized: {}", path),
            };
        }
    };

    if !normalized.is_dir() {
        return RootDecision::Reject {
            reason: "Path is not a directory".to_string(),
        };
    }

    // Promote subdirectory to git root if applicable
    let root = promote_to_git_root(&normalized, &home);
    let root_str = root.to_string_lossy();

    // Reject broad paths
    if is_broad_reject_path(&root, &home) {
        if !has_project_marker(&root) {
            debug!("Root rejected (too broad): {}", root_str);
            return RootDecision::Reject {
                reason: "Path is too broad (home, Documents, Desktop, etc.)".to_string(),
            };
        }
    }

    // Reject if depth too shallow (e.g. /Users/me or /Users/me/code)
    if let Some(depth) = path_depth_under_home(&root, &home) {
        if depth < MIN_DEPTH_UNDER_HOME && !has_project_marker(&root) {
            debug!("Root rejected (depth too shallow): {}", root_str);
            return RootDecision::Reject {
                reason: format!(
                    "Path depth under home is too shallow ({} < {} components)",
                    depth, MIN_DEPTH_UNDER_HOME
                ),
            };
        }
    }

    // Accept if project marker exists
    if has_project_marker(&root) {
        return RootDecision::Accept {
            normalized_root: root.clone(),
            reason: "Project marker found (.git or package.json, etc.)".to_string(),
        };
    }

    RootDecision::Reject {
        reason: "No project marker (.git, Cargo.toml, package.json, etc.)".to_string(),
    }
}

/// Count of roots rejected by policy (for metrics). Reserved for future use.
#[allow(dead_code)]
#[derive(Default)]
pub struct RootPolicyMetrics {
    pub rejects: u64,
}

#[allow(dead_code)]
impl RootPolicyMetrics {
    pub fn record_reject(&mut self) {
        self.rejects += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> String {
        std::env::var_os("HOME")
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|| "/tmp".to_string())
    }

    #[test]
    fn reject_home() {
        let h = home();
        let decision = evaluate_root(&h);
        match &decision {
            RootDecision::Reject { reason } => assert!(reason.contains("broad") || reason.contains("marker")),
            RootDecision::Accept { .. } => {
                // Could accept if ~/.git exists (unusual)
                assert!(Path::new(&h).join(".git").exists() || Path::new(&h).join("Cargo.toml").exists());
            }
        }
    }

    #[test]
    fn accept_git_repo() {
        let tmp = std::env::temp_dir();
        let repo = tmp.join(format!("antidote_rootpolicy_git_{}", std::process::id()));
        let _ = std::fs::create_dir_all(repo.join(".git"));
        let decision = evaluate_root(repo.to_str().unwrap());
        let _ = std::fs::remove_dir_all(&repo);
        match &decision {
            RootDecision::Accept { reason, .. } => assert!(reason.contains("marker") || reason.contains(".git")),
            RootDecision::Reject { reason } => panic!("Expected accept, got reject: {}", reason),
        }
    }

    #[test]
    fn accept_cargo_toml() {
        let tmp = std::env::temp_dir();
        let proj = tmp.join(format!("antidote_rootpolicy_cargo_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&proj);
        let _ = std::fs::write(proj.join("Cargo.toml"), "");
        let decision = evaluate_root(proj.to_str().unwrap());
        let _ = std::fs::remove_dir_all(&proj);
        match &decision {
            RootDecision::Accept { .. } => {}
            RootDecision::Reject { reason } => panic!("Expected accept, got reject: {}", reason),
        }
    }

    #[test]
    fn promote_subdir_to_git_root() {
        let tmp = std::env::temp_dir();
        let repo = tmp.join(format!("antidote_rootpolicy_promote_{}", std::process::id()));
        let subdir = repo.join("src").join("sub");
        let _ = std::fs::create_dir_all(repo.join(".git"));
        let _ = std::fs::create_dir_all(&subdir);
        let decision = evaluate_root(subdir.to_str().unwrap());
        let _ = std::fs::remove_dir_all(&repo);
        match &decision {
            RootDecision::Accept { normalized_root, .. } => {
                assert!(normalized_root.ends_with("antidote_rootpolicy_promote"));
            }
            RootDecision::Reject { reason } => panic!("Expected accept (promoted), got reject: {}", reason),
        }
    }

    #[test]
    fn normalize_expands_tilde() {
        if std::env::var_os("HOME").is_some() {
            let n = normalize_path("~/foo");
            assert!(n.is_some());
            assert!(n.unwrap().to_string_lossy().contains("foo"));
        }
    }
}
