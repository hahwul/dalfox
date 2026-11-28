use std::io;

use rmcp::RoleServer;
use rmcp::service::{RxJsonRpcMessage, TxJsonRpcMessage};
use rmcp::transport::{Transport, async_rw::AsyncRwTransport};
use tokio::io::{AsyncRead, AsyncWrite};

use super::DalfoxMcp;

pub(super) struct SessionTransport<R: AsyncRead, W: AsyncWrite> {
    io: AsyncRwTransport<RoleServer, R, W>,
    session: DalfoxMcp,
}

impl<R, W> SessionTransport<R, W>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    pub(super) fn new(read: R, write: W, session: DalfoxMcp) -> Self {
        Self {
            io: AsyncRwTransport::new(read, write),
            session,
        }
    }
}

impl<R, W> Transport<RoleServer> for SessionTransport<R, W>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    type Error = io::Error;

    fn send(
        &mut self,
        message: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        self.io.send(message)
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        let message = self.io.receive().await;
        if message.is_none() {
            // rmcp may spend several seconds draining replies after EOF.
            self.session.disconnect();
        }
        message
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.session.disconnect();
        self.io.close().await
    }
}
