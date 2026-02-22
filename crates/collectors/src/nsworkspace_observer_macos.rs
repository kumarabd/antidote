//! NSWorkspace notification observers (Phase 2: event-driven).
//! - App lifecycle: launch/terminate (runs alongside poll-based app detector).
//! - Foreground: activate app (runs alongside ForegroundPoller; events primary, poll fallback).

use super::app_detector_macos::{default_signatures, match_app, AppEvent, AppKind, AppSignature};
use super::foreground_macos::ForegroundApp;
use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2_app_kit::{
    NSRunningApplication, NSWorkspace, NSWorkspaceApplicationKey,
    NSWorkspaceDidActivateApplicationNotification, NSWorkspaceDidLaunchApplicationNotification,
    NSWorkspaceDidTerminateApplicationNotification,
};
use objc2_foundation::{NSNotification, NSOperationQueue};
use std::ptr::NonNull;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Spawns a task that observes NSWorkspace launch/terminate notifications and forwards to the
/// app event channel. Runs until shutdown. Use as the primary app lifecycle source; keep poll
/// as 60s reconciliation fallback.
pub fn spawn_nsworkspace_observer(
    event_tx: mpsc::Sender<AppEvent>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (launch_tx, mut launch_rx) = tokio::sync::mpsc::unbounded_channel::<AppEvent>();
        let (term_tx, mut term_rx) = tokio::sync::mpsc::unbounded_channel::<AppEvent>();

        let result = std::thread::spawn(move || {
            run_observer(launch_tx, term_tx);
        });

        info!("NSWorkspace observer started (event-driven app lifecycle)");

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("NSWorkspace observer shutting down");
                    break;
                }
                Some(ev) = launch_rx.recv() => {
                    if event_tx.send(ev).await.is_err() {
                        warn!("App event channel closed");
                        break;
                    }
                }
                Some(ev) = term_rx.recv() => {
                    if event_tx.send(ev).await.is_err() {
                        warn!("App event channel closed");
                        break;
                    }
                }
            }
        }

        if let Err(e) = result.join() {
            warn!("NSWorkspace observer thread panicked: {:?}", e);
        }
    })
}

fn run_observer(
    launch_tx: tokio::sync::mpsc::UnboundedSender<AppEvent>,
    term_tx: tokio::sync::mpsc::UnboundedSender<AppEvent>,
) {
    let workspace = NSWorkspace::sharedWorkspace();
    let center = workspace.notificationCenter();
    let queue = NSOperationQueue::new();

    let signatures = default_signatures();

    let launch_tx = std::sync::Arc::new(launch_tx);
    let term_tx = std::sync::Arc::new(term_tx);

    {
        let tx = launch_tx.clone();
        let sigs = signatures.clone();
        let block = RcBlock::new(move |notification: NonNull<NSNotification>| {
            if let Some(ev) = handle_launch_notification(notification, &sigs) {
                let _ = tx.send(ev);
            }
        });
        unsafe {
            center.addObserverForName_object_queue_usingBlock(
                Some(NSWorkspaceDidLaunchApplicationNotification),
                None,
                Some(&queue),
                &block,
            );
        }
    }

    {
        let tx = term_tx.clone();
        let sigs = signatures;
        let block = RcBlock::new(move |notification: NonNull<NSNotification>| {
            if let Some(ev) = handle_terminate_notification(notification, &sigs) {
                let _ = tx.send(ev);
            }
        });
        unsafe {
            center.addObserverForName_object_queue_usingBlock(
                Some(NSWorkspaceDidTerminateApplicationNotification),
                None,
                Some(&queue),
                &block,
            );
        }
    }

    std::thread::park();
}

fn extract_app_from_notification(
    notification: NonNull<NSNotification>,
    signatures: &[AppSignature],
) -> Option<(AppKind, i32, String, Option<String>)> {
    let notification = unsafe { notification.as_ref() };
    let user_info = notification.userInfo()?;
    let app_obj: Retained<AnyObject> = unsafe { user_info.objectForKey(NSWorkspaceApplicationKey)? };
    let app = app_obj.downcast::<NSRunningApplication>().ok()?;
    let pid = app.processIdentifier();
    let name = app
        .localizedName()
        .map(|s| s.to_string())
        .unwrap_or_default();
    let bundle_id = app
        .bundleIdentifier()
        .map(|s| s.to_string());
    let app_kind = match_app(&name, signatures)?;
    Some((app_kind, pid, name, bundle_id))
}

fn handle_launch_notification(
    notification: NonNull<NSNotification>,
    signatures: &[AppSignature],
) -> Option<AppEvent> {
    let (app, pid, name, bundle_id) = extract_app_from_notification(notification, signatures)?;
    debug!("NSWorkspace launch: {} pid={}", app.as_display_str(), pid);
    Some(AppEvent::Started {
        app,
        pid,
        process_name: Some(name),
        bundle_id,
        started_at: OffsetDateTime::now_utc(),
    })
}

fn handle_terminate_notification(
    notification: NonNull<NSNotification>,
    signatures: &[AppSignature],
) -> Option<AppEvent> {
    let (app, pid, _name, _bundle_id) = extract_app_from_notification(notification, signatures)?;
    debug!("NSWorkspace terminate: {} pid={}", app.as_display_str(), pid);
    Some(AppEvent::Exited {
        app,
        pid,
        exited_at: OffsetDateTime::now_utc(),
    })
}

// --- Foreground activate observer ---

/// Spawns a task that observes `NSWorkspaceDidActivateApplicationNotification` and forwards
/// `ForegroundApp` updates to the given channel. Use as primary source for foreground app;
/// keep ForegroundPoller at 30s reconciliation poll.
pub fn spawn_foreground_activate_observer(
    event_tx: tokio::sync::mpsc::UnboundedSender<ForegroundApp>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (activate_tx, mut activate_rx) = tokio::sync::mpsc::unbounded_channel::<ForegroundApp>();

        let result = std::thread::spawn(move || run_activate_observer(activate_tx));

        info!("NSWorkspace foreground activate observer started (event-driven)");

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Foreground activate observer shutting down");
                    break;
                }
                Some(app) = activate_rx.recv() => {
                    if event_tx.send(app).is_err() {
                        warn!("Foreground event channel closed");
                        break;
                    }
                }
            }
        }

        if let Err(e) = result.join() {
            warn!("Foreground activate observer thread panicked: {:?}", e);
        }
    })
}

fn run_activate_observer(tx: tokio::sync::mpsc::UnboundedSender<ForegroundApp>) {
    let workspace = NSWorkspace::sharedWorkspace();
    let center = workspace.notificationCenter();
    let queue = NSOperationQueue::new();

    let tx = std::sync::Arc::new(tx);

    let block = RcBlock::new(move |notification: NonNull<NSNotification>| {
        if let Some(app) = extract_foreground_from_activate(notification) {
            let _ = tx.send(app);
        }
    });
    unsafe {
        center.addObserverForName_object_queue_usingBlock(
            Some(NSWorkspaceDidActivateApplicationNotification),
            None,
            Some(&queue),
            &block,
        );
    }

    std::thread::park();
}

fn extract_foreground_from_activate(notification: NonNull<NSNotification>) -> Option<ForegroundApp> {
    let notification = unsafe { notification.as_ref() };
    let user_info = notification.userInfo()?;
    let app_obj: Retained<AnyObject> = unsafe { user_info.objectForKey(NSWorkspaceApplicationKey)? };
    let app = app_obj.downcast::<NSRunningApplication>().ok()?;
    let pid = app.processIdentifier();
    let name = app
        .localizedName()
        .map(|s| s.to_string())
        .unwrap_or_default();
    if name.is_empty() {
        return None;
    }
    let bundle_id = app.bundleIdentifier().map(|s| s.to_string());
    Some(ForegroundApp {
        name,
        pid: Some(pid),
        bundle_id,
        observed_at: OffsetDateTime::now_utc(),
    })
}
