//! Diagnostics export: one-click zip for support.

use super::ApiState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use std::io::Write;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

/// Redact secrets from config content.
pub fn redact_config(content: &str) -> String {
    let mut out = String::new();
    for line in content.lines() {
        let lower = line.to_lowercase();
        if lower.contains("token")
            || lower.contains("key")
            || lower.contains("secret")
            || lower.contains("password")
        {
            if let Some((before, _)) = line.split_once('=') {
                out.push_str(before);
                out.push_str("= \"***REDACTED***\"\n");
                continue;
            }
            if let Some((before, _)) = line.split_once(':') {
                out.push_str(before);
                out.push_str(": \"***REDACTED***\"\n");
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[derive(Debug, Deserialize)]
pub struct ExportParams {
    pub include_logs: Option<bool>,
    pub include_config: Option<bool>,
}

/// POST /support/diagnostics/export
pub async fn diagnostics_export_handler(
    State(state): State<ApiState>,
    Query(params): Query<ExportParams>,
) -> impl IntoResponse {
    let include_logs = params.include_logs.unwrap_or(true);
    let include_config = params.include_config.unwrap_or(true);

    let ts = time::OffsetDateTime::now_utc();
    let ts_str = ts
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string());
    let ts_clean: String = ts_str
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(20)
        .collect();
    let safe_filename = format!("antidote-diagnostics-{}.zip", ts_clean);

    let mut buf = Vec::new();
    let mut zip = ZipWriter::new(std::io::Cursor::new(&mut buf));
    let opts = SimpleFileOptions::default().unix_permissions(0o644);

    let add_json = |zip: &mut ZipWriter<_>, path: &str, data: &serde_json::Value| {
        let s = serde_json::to_string_pretty(data).unwrap_or_else(|_| "{}".to_string());
        zip.start_file(path, opts).ok()?;
        zip.write_all(s.as_bytes()).ok()?;
        Some(())
    };

    // diagnostics.json (zero_config_status / snapshot)
    let diag = build_diagnostics_snapshot(&state).await;
    let _ = add_json(&mut zip, "diagnostics.json", &diag);

    // health.json
    let health = build_health_snapshot(&state).await;
    let _ = add_json(&mut zip, "health.json", &health);

    // confidence.json
    let confidence = build_confidence_snapshot(&state).await;
    let _ = add_json(&mut zip, "confidence.json", &confidence);

    // warnings.json
    let warnings = build_warnings_snapshot(&state).await;
    let _ = add_json(&mut zip, "warnings.json", &warnings);

    // pipeline.json
    let pipeline = if let Some(ref ti) = state.telemetry_integrity {
        ti.clone().get_pipeline().await
    } else {
        serde_json::json!({})
    };
    let _ = add_json(&mut zip, "pipeline.json", &pipeline);

    // sessions_recent.json
    let sessions = state
        .storage
        .list_sessions(Some(20), None, None, None)
        .await
        .unwrap_or_default();
    let sessions_json: Vec<serde_json::Value> = sessions
        .into_iter()
        .map(|s| {
            serde_json::json!({
                "session_id": s.session_id,
                "app": s.app,
                "start_ts": s.start_ts.to_string(),
                "end_ts": s.end_ts.map(|t| t.to_string()),
                "summary_json": s.summary_json,
            })
        })
        .collect();
    let _ = add_json(&mut zip, "sessions_recent.json", &serde_json::json!(sessions_json));

    // system.json
    let hostname_str = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());
    let system = serde_json::json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "hostname": hostname_str,
        "app_version": env!("CARGO_PKG_VERSION"),
        "daemon_version": env!("CARGO_PKG_VERSION"),
        "build_sha": option_env!("GIT_SHA").unwrap_or("unknown"),
    });
    let _ = add_json(&mut zip, "system.json", &system);

    if include_config {
        let config_path = std::path::Path::new("config.toml");
        let rules_path = std::path::Path::new("rules/rules.yaml");
        let config_content = std::fs::read_to_string(config_path)
            .ok()
            .map(|c| redact_config(&c))
            .unwrap_or_else(|| "# Config not found\n".to_string());
        let rules_content = std::fs::read_to_string(rules_path)
            .ok()
            .map(|c| redact_config(&c))
            .unwrap_or_else(|| "# Rules not found\n".to_string());
        let _ = zip.start_file("config/config.toml", opts);
        let _ = zip.write_all(config_content.as_bytes());
        let _ = zip.start_file("config/rules.yaml", opts);
        let _ = zip.write_all(rules_content.as_bytes());
    }

    if include_logs {
        let log_content = fetch_log_tail(500).await;
        if let Some(content) = log_content {
            let _ = zip.start_file("logs/daemon.log", opts);
            let _ = zip.write_all(content.as_bytes());
        } else {
            let readme = "No log file configured; using stdout only.";
            let _ = zip.start_file("logs/README.txt", opts);
            let _ = zip.write_all(readme.as_bytes());
        }
    }

    if let Err(e) = zip.finish() {
        tracing::error!("Failed to finish zip: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(axum::http::header::CONTENT_TYPE, "text/plain")],
            format!("Failed to create diagnostics zip: {}", e),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "application/zip"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", safe_filename).as_str(),
            ),
        ],
        buf,
    )
        .into_response()
}

async fn build_diagnostics_snapshot(state: &ApiState) -> serde_json::Value {
    let roots = state.storage.list_watched_roots().await.unwrap_or_default();
    let watchers = match &state.fs_watcher {
        Some(w) => serde_json::to_value(w.read().await.watcher_status()).unwrap_or(serde_json::json!([])),
        None => serde_json::json!([]),
    };
    let pipeline = if let Some(ref ti) = state.telemetry_integrity {
        ti.clone().get_pipeline().await
    } else {
        serde_json::json!({})
    };
    let dropped = state.drop_metrics.as_ref().map(|m| m.get_dropped()).unwrap_or(0);
    let attr_quality = if let Some(ref ti) = state.telemetry_integrity {
        ti.clone().get_attribution_quality().await
    } else {
        serde_json::json!({})
    };
    serde_json::json!({
        "root_count": roots.len(),
        "watchers": watchers,
        "roots": roots,
        "pipeline": pipeline,
        "dropped_events": dropped,
        "attribution_quality": attr_quality,
        "proxy_enabled": state.proxy_enabled,
    })
}

async fn build_health_snapshot(state: &ApiState) -> serde_json::Value {
    let mut components = Vec::new();
    if let Some(ref w) = state.fs_watcher {
        let watchers = w.read().await.watcher_status();
        components.push(serde_json::json!({
            "name": "FsWatcherManager",
            "healthy": !watchers.is_empty(),
            "running": true,
        }));
    }
    components.push(serde_json::json!({
        "name": "AttributionEngine",
        "healthy": state.attribution_debug.is_some(),
        "running": true,
    }));
    let system_healthy = components.iter().all(|c| c.get("healthy").and_then(|v| v.as_bool()).unwrap_or(false));
    serde_json::json!({
        "components": components,
        "system_healthy": system_healthy,
    })
}

async fn build_confidence_snapshot(state: &ApiState) -> serde_json::Value {
    let fs_active = match &state.fs_watcher {
        Some(w) => !w.read().await.watcher_status().is_empty(),
        None => false,
    };
    let proxy_active = state.proxy_enabled;
    let (global, reasons) = if fs_active && proxy_active {
        ("High", vec![] as Vec<String>)
    } else {
        let mut r = Vec::new();
        if !fs_active {
            r.push("fs_watcher_inactive".to_string());
        }
        if !proxy_active {
            r.push("proxy_disabled".to_string());
        }
        ("Low", r)
    };
    serde_json::json!({
        "global": global,
        "global_reasons": reasons,
        "per_session": [],
    })
}

async fn build_warnings_snapshot(state: &ApiState) -> serde_json::Value {
    let mut warnings: Vec<serde_json::Value> = Vec::new();
    #[cfg(target_os = "macos")]
    {
        let cursor_running = if let Some(ref g) = state.app_detector_state {
            let s = g.read().await;
            s.instances
                .iter()
                .any(|i| format!("{:?}", i.app).to_lowercase().contains("cursor"))
        } else {
            false
        };
        let workspace_detected = if let Some(ref g) = state.workspace_resolver_state {
            let s = g.read().await;
            !s.items.is_empty()
        } else {
            false
        };
        if cursor_running && !workspace_detected {
            warnings.push(serde_json::json!({
                "code": "WORKSPACE_MISSING",
                "severity": "medium",
                "message": "Workspace resolution inactive",
            }));
        }
    }
    serde_json::json!({ "warnings": warnings })
}

async fn fetch_log_tail(lines: usize) -> Option<String> {
    let candidates = ["antidote.log", "daemon.log", "/tmp/antidote.log"];
    for path in &candidates {
        if let Ok(content) = tokio::fs::read_to_string(path).await {
            let line_list: Vec<&str> = content.lines().collect();
            let start = line_list.len().saturating_sub(lines);
            let tail = line_list[start..].join("\n");
            return Some(tail);
        }
    }
    None
}
