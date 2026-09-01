use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultMode {
    Pass,
    Blackhole,
    Reset,
}

pub struct FaultProxy {
    address: SocketAddr,
    mode: watch::Sender<FaultMode>,
    shutdown: CancellationToken,
    owner: Option<JoinHandle<()>>,
}

impl FaultProxy {
    pub async fn start(target: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (mode, _) = watch::channel(FaultMode::Pass);
        let shutdown = CancellationToken::new();
        let owner_shutdown = shutdown.clone();
        let owner_mode = mode.clone();
        let owner = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = owner_shutdown.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((client, _)) = accepted else { break };
                        let receiver = owner_mode.subscribe();
                        let child_shutdown = owner_shutdown.clone();
                        tokio::spawn(proxy_connection(client, target, receiver, child_shutdown));
                    }
                }
            }
        });
        Self {
            address,
            mode,
            shutdown,
            owner: Some(owner),
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn set_mode(&self, mode: FaultMode) {
        self.mode.send_replace(mode);
    }

    pub async fn shutdown(mut self) {
        self.shutdown.cancel();
        if let Some(mut owner) = self.owner.take()
            && tokio::time::timeout(Duration::from_secs(2), &mut owner)
                .await
                .is_err()
        {
            owner.abort();
            let _ = owner.await;
        }
    }
}

impl Drop for FaultProxy {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(owner) = self.owner.take() {
            owner.abort();
        }
    }
}

async fn proxy_connection(
    mut client: TcpStream,
    target: SocketAddr,
    mut mode: watch::Receiver<FaultMode>,
    shutdown: CancellationToken,
) {
    let Ok(mut server) = TcpStream::connect(target).await else {
        return;
    };
    loop {
        let current = *mode.borrow_and_update();
        match current {
            FaultMode::Pass => {
                tokio::select! {
                    () = shutdown.cancelled() => return,
                    changed = mode.changed() => {
                        if changed.is_err() { return; }
                    }
                    _ = copy_bidirectional(&mut client, &mut server) => return,
                }
            }
            FaultMode::Blackhole => {
                tokio::select! {
                    () = shutdown.cancelled() => return,
                    changed = mode.changed() => {
                        if changed.is_err() { return; }
                    }
                }
            }
            FaultMode::Reset => return,
        }
    }
}
