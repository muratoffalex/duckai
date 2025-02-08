use std::time::Duration;

use axum_server::Handle;
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::sleep;
use tracing::info;

pub(super) async fn graceful_shutdown(handle: Handle) {
    let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM signal hanlde error");
    let mut sigquit = signal(SignalKind::quit()).expect("SIGQUIT signal hanlde error");
    let mut sigchld = signal(SignalKind::child()).expect("SIGCHLD signal hanlde error");
    let mut sighup = signal(SignalKind::hangup()).expect("SIGHUP signal hanlde error");
    tokio::select! {
        _ = sigterm.recv() => {
            sending_graceful_shutdown_signal(handle, "SIGTERM").await;
        },
        _ = sigquit.recv() => {
            sending_graceful_shutdown_signal(handle, "SIGQUIT").await;
        },
        _ = sigchld.recv() => {
            sending_graceful_shutdown_signal(handle, "SIGCHLD").await;
        },
        _ = sighup.recv() => {
            sending_graceful_shutdown_signal(handle, "SIGHUP").await;
        },
        _ = tokio::signal::ctrl_c() => {
            sending_graceful_shutdown_signal(handle, "SIGINT").await;
        }
    };
}

async fn sending_graceful_shutdown_signal(handle: Handle, signal: &'static str) {
    info!("{signal} received: starting graceful shutdown");

    // Signal the server to shutdown using Handle.
    handle.graceful_shutdown(Some(Duration::from_secs(1)));

    // Print alive connection count every second.
    loop {
        sleep(Duration::from_secs(1)).await;
        info!("Alive connections: {}", handle.connection_count());
    }
}
