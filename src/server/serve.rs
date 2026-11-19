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
//!
//! Here every state a connection can sit in has a deadline — reading a request
//! head (which is also the keep-alive idle wait), reading a body
//! ([`body_deadline`]), and writing to a peer that has stopped reading
//! ([`StallGuard`]) — and the number of connections is capped below the
//! process's fd limit.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper_util::rt::{TokioIo, TokioTimer};

/// The one timeout a connection runs under: how long it may take to deliver a
/// request head (from connect, and again from the end of each response, so
/// this is the keep-alive idle timeout too), how long a whole request body may
/// take, and how long a write may make no progress. nginx's defaults for the
/// same three are 60s / 60s / 60s.
pub(crate) const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// Connection cap where the process's fd limit cannot be read (anything but
/// Linux). macOS's default soft limit is 256.
const FALLBACK_MAX_CONNECTIONS: usize = 128;

/// Open API connections served at once: half the process's open-file limit,
/// so the other half stays free for the scans' own sockets. Past the cap, new
/// connections wait in the kernel backlog instead of each taking an fd.
pub(crate) fn max_connections() -> usize {
    let soft_limit = std::fs::read_to_string("/proc/self/limits")
        .ok()
        .and_then(|limits| nofile_soft_limit(&limits));
    connections_for(soft_limit)
}

fn connections_for(nofile_soft_limit: Option<usize>) -> usize {
    nofile_soft_limit.map_or(FALLBACK_MAX_CONNECTIONS, |limit| {
        (limit / 2).clamp(FALLBACK_MAX_CONNECTIONS, 65_536)
    })
}

/// The soft `Max open files` value out of `/proc/self/limits`.
fn nofile_soft_limit(limits: &str) -> Option<usize> {
    limits
        .lines()
        .find_map(|line| line.strip_prefix("Max open files"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Request-body middleware: the whole body must arrive within `timeout` of the
/// request head. A deadline rather than a gap between chunks — one byte every
/// few seconds resets a gap forever, and a body is read before the handler
/// can check an API key. Past it the body read fails, which the handlers
/// answer as a 400.
pub(crate) async fn body_deadline(
    timeout: Duration,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use futures::StreamExt;
    let deadline = tokio::time::Instant::now() + timeout;
    let request = request.map(|body| {
        let chunks =
            futures::stream::unfold(body.into_data_stream(), move |mut chunks| async move {
                match tokio::time::timeout_at(deadline, chunks.next()).await {
                    Ok(chunk) => chunk.map(|chunk| (chunk.map_err(std::io::Error::other), chunks)),
                    Err(_) => Some((
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("request body not received within {}s", timeout.as_secs()),
                        )),
                        chunks,
                    )),
                }
            });
        axum::body::Body::from_stream(chunks)
    });
    next.run(request).await
}

/// A connection whose writes fail once the peer has taken nothing for
/// `timeout`. hyper bounds neither a response write nor the connection as a
/// whole, so a client that requests a large result and stops reading would
/// hold its slot until the process exits.
struct StallGuard {
    stream: tokio::net::TcpStream,
    timeout: Duration,
    stalled: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl tokio::io::AsyncRead for StallGuard {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for StallGuard {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        match Pin::new(&mut this.stream).poll_write(cx, buf) {
            Poll::Pending => {
                let timeout = this.timeout;
                let stalled = this
                    .stalled
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
                stalled
                    .as_mut()
                    .poll(cx)
                    .map(|()| Err(std::io::ErrorKind::TimedOut.into()))
            }
            wrote => {
                this.stalled = None;
                wrote
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Serve `app` on `listener` until `shutdown` resolves, then stop accepting,
/// let in-flight requests finish, and close idle connections.
pub(crate) async fn serve_connections(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    shutdown: impl Future<Output = ()>,
    timeout: Duration,
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
                .header_read_timeout(timeout)
                .serve_connection(
                    TokioIo::new(StallGuard {
                        stream,
                        timeout,
                        stalled: None,
                    }),
                    service,
                );
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
    /// More than loopback socket buffers hold, so an unread response stalls.
    const BIG: usize = 64 * 1024 * 1024;

    /// Serve `/` (answers after 300ms) and `/big`; returns the address and the
    /// shutdown trigger.
    async fn spawn_server(
        timeout: Duration,
        max_connections: usize,
    ) -> (
        std::net::SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let app = axum::Router::new()
            .route(
                "/",
                axum::routing::get(|| async {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    "ok"
                }),
            )
            .route("/big", axum::routing::get(|| async { vec![b'x'; BIG] }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let served = tokio::spawn(serve_connections(
            listener,
            app,
            async {
                let _ = rx.await;
            },
            timeout,
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

    /// Send a request and wait for the first byte of the reply.
    async fn first_byte_after(conn: &mut TcpStream, request: &[u8]) -> Duration {
        let started = tokio::time::Instant::now();
        conn.write_all(request).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), conn.read_u8())
            .await
            .expect("the server must answer")
            .expect("a reply, not a closed connection");
        started.elapsed()
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
        let (addr, _stop, _served) = spawn_server(Duration::from_millis(600), 1).await;
        // Takes the only slot and never sends a request.
        let _hog = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut conn = TcpStream::connect(addr).await.unwrap();
        // Uncapped this is the handler's 300ms; capped, the hog's 600ms first.
        let waited = first_byte_after(&mut conn, GET).await;
        assert!(
            waited >= Duration::from_millis(700),
            "served after {waited:?}, before the hog's slot was reclaimed"
        );
    }

    #[tokio::test]
    async fn a_client_that_stops_reading_loses_its_connection() {
        let (addr, _stop, _served) = spawn_server(Duration::from_millis(300), 1).await;
        // Asks for a response far larger than the socket buffers and never
        // reads it, on the only slot.
        let mut stalled = TcpStream::connect(addr).await.unwrap();
        stalled
            .write_all(b"GET /big HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        // Served only once the stalled write has been given up on.
        let mut conn = TcpStream::connect(addr).await.unwrap();
        first_byte_after(&mut conn, GET).await;
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

    #[test]
    fn the_connection_cap_is_half_the_fd_limit() {
        let limits = "Limit                     Soft Limit           Hard Limit           Units     \n\
                      Max processes             63204                63204                processes \n\
                      Max open files            1024                 524288               files     \n";
        assert_eq!(nofile_soft_limit(limits), Some(1024));
        assert_eq!(
            nofile_soft_limit("Max open files  unlimited  unlimited  files"),
            None
        );
        assert_eq!(nofile_soft_limit(""), None);

        assert_eq!(connections_for(Some(1024)), 512);
        // Never below the fallback, never an unbounded number of tasks.
        assert_eq!(connections_for(Some(64)), FALLBACK_MAX_CONNECTIONS);
        assert_eq!(connections_for(Some(1_048_576)), 65_536);
        assert_eq!(connections_for(None), FALLBACK_MAX_CONNECTIONS);
        assert!(max_connections() >= FALLBACK_MAX_CONNECTIONS);
    }
}
