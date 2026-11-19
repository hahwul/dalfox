//! The accept loop, in place of `axum::serve`.
//!
//! `axum::serve` exposes no connection limits at all: it builds hyper without
//! a timer, so a connection that never finishes its request head — or one left
//! idle after a response — is held open forever. Each costs a file descriptor,
//! and nothing needs an API key to open one, so a client that died mid-request,
//! a laptop that went to sleep, or a few hundred deliberate half-open sockets
//! all end the same way: the process hits its fd limit, the API stops
//! answering, and the scans already running can no longer open sockets to
//! their targets.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::{TokioIo, TokioTimer};

/// How long a connection may take to deliver a request head — from connect,
/// and again from the end of each response, so this is the keep-alive idle
/// timeout too. Also the gap allowed between two chunks of a request body
/// (`build_router`). nginx's defaults for the same three are 60s / 75s / 60s.
pub(crate) const CONNECTION_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Open API connections served at once. Past it, new ones wait in the kernel
/// backlog rather than each taking a file descriptor, so the common 1024-fd
/// soft limit keeps room for the scans' own sockets.
pub(crate) const MAX_CONNECTIONS: usize = 256;

/// Serve `app` on `listener` until `shutdown` resolves, then stop accepting,
/// let in-flight requests finish, and close idle connections.
pub(crate) async fn serve_connections(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    shutdown: impl Future<Output = ()>,
    read_timeout: Duration,
    max_connections: usize,
) {
    // Clamped once for the drain below, and again in the call itself because
    // `every_semaphore_new_clamps_its_permit_count` reads the argument text.
    let max_connections = crate::utils::semaphore_permits(max_connections);
    let slots = Arc::new(tokio::sync::Semaphore::new(
        crate::utils::semaphore_permits(max_connections),
    ));
    // Dropped on the way out, which wakes every connection task.
    let (closing_tx, closing_rx) = tokio::sync::watch::channel(());
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        // The slot comes first: at the cap nothing is accepted.
        let next = async {
            let slot = slots.clone().acquire_owned().await;
            (listener.accept().await, slot)
        };
        let (accepted, slot) = tokio::select! {
            _ = &mut shutdown => break,
            next = next => next,
        };
        let stream = match accepted {
            Ok((stream, _)) => stream,
            Err(e) => {
                // `axum::serve`'s policy: a connection that died in the
                // backlog is skipped; anything else (EMFILE above all) backs
                // off instead of spinning on the same error.
                use std::io::ErrorKind::{ConnectionAborted, ConnectionRefused, ConnectionReset};
                if !matches!(
                    e.kind(),
                    ConnectionAborted | ConnectionRefused | ConnectionReset
                ) {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
        };
        let service = hyper_util::service::TowerToHyperService::new(app.clone());
        let mut closing = closing_rx.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(read_timeout)
                .serve_connection(TokioIo::new(stream), service);
            let mut conn = std::pin::pin!(conn);
            tokio::select! {
                _ = conn.as_mut() => {}
                _ = closing.changed() => {
                    conn.as_mut().graceful_shutdown();
                    let _ = conn.await;
                }
            }
        });
    }
    drop(listener);
    drop(closing_tx);
    // Every slot back means every connection task has ended.
    let _ = slots.acquire_many(max_connections as u32).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";

    /// Serve a one-route app; returns its address and the shutdown trigger.
    async fn spawn_server(
        read_timeout: Duration,
        max_connections: usize,
    ) -> (
        std::net::SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(|| async {
                tokio::time::sleep(Duration::from_millis(300)).await;
                "ok"
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let served = tokio::spawn(serve_connections(
            listener,
            app,
            async {
                let _ = rx.await;
            },
            read_timeout,
            max_connections,
        ));
        (addr, tx, served)
    }

    /// Read until the server closes the connection, or panic after 5s.
    async fn read_to_close(conn: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), conn.read_to_end(&mut buf))
            .await
            .expect("the server must close the connection")
            .ok();
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[tokio::test]
    async fn a_stalled_request_head_is_closed() {
        let (addr, _stop, _served) = spawn_server(Duration::from_millis(200), 8).await;
        let mut conn = TcpStream::connect(addr).await.unwrap();
        conn.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nX-Never: ")
            .await
            .unwrap();
        assert!(!read_to_close(&mut conn).await.contains("200 OK"));
    }

    #[tokio::test]
    async fn an_idle_keep_alive_connection_is_closed() {
        let (addr, _stop, _served) = spawn_server(Duration::from_millis(200), 8).await;
        let mut conn = TcpStream::connect(addr).await.unwrap();
        conn.write_all(GET).await.unwrap();
        // The response arrives, then the idle connection is reaped.
        assert!(read_to_close(&mut conn).await.contains("200 OK"));
    }

    #[tokio::test]
    async fn past_the_cap_a_connection_waits_for_a_slot() {
        let (addr, _stop, _served) = spawn_server(Duration::from_millis(400), 1).await;
        // Takes the only slot and never sends a request.
        let _hog = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let started = tokio::time::Instant::now();
        let mut conn = TcpStream::connect(addr).await.unwrap();
        conn.write_all(GET).await.unwrap();
        assert!(read_to_close(&mut conn).await.contains("200 OK"));
        assert!(
            started.elapsed() >= Duration::from_millis(300),
            "served before the hog's slot was reclaimed"
        );
    }

    #[tokio::test]
    async fn shutdown_finishes_the_request_in_flight_and_drops_idle_connections() {
        let (addr, stop, served) = spawn_server(Duration::from_secs(30), 8).await;
        let _idle = TcpStream::connect(addr).await.unwrap();
        let mut busy = TcpStream::connect(addr).await.unwrap();
        busy.write_all(GET).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        stop.send(()).unwrap();
        assert!(read_to_close(&mut busy).await.contains("200 OK"));
        tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("serve must return once its connections are done")
            .unwrap();
    }
}
