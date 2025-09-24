use std::{
    future::Future,
    io,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use log::{debug, error};

use crate::{
    RUNTIME,
    config::Config,
    context::*,
    runtime,
    tls::{self, alert},
    zc,
};

/// Starts a TCP server on `bind` and use the given `handle_stream` function to
/// process incoming connections.
pub(crate) fn listen_and_proxy<Fut>(
    config: Arc<Config>,
    bind: SocketAddr,
    handle_stream: fn(Arc<Config>, TcpStream) -> Fut,
) -> Result<()>
where
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let runtime = runtime!()?;
    let listener = TcpListener::bind(bind)?;

    // Do not return an error starting from here, this would close the whole
    // listener.

    for stream in listener.incoming() {
        // Do not fail on stream errors.
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(e) => {
                error!("Connection error: {e}");
                continue;
            }
        };

        // Extract peer & local addresses w/o failing the whole listener in case
        // of errors.
        let local = match stream.local_addr() {
            Ok(local) => local,
            Err(e) => {
                match e.kind() {
                    // Even in this small window the client could close the connection.
                    io::ErrorKind::NotConnected => continue,
                    _ => {
                        error!("Could not get local address: {e}");
                        continue;
                    }
                }
            }
        };
        let peer = match stream.peer_addr() {
            Ok(peer) => peer,
            Err(e) => {
                match e.kind() {
                    // Even in this small window the client could close the connection.
                    io::ErrorKind::NotConnected => continue,
                    _ => {
                        error!("Could not get peer address: {e}");
                        continue;
                    }
                }
            }
        };

        // Handle the connection async.
        let config = Arc::clone(&config);
        runtime.spawn(with_req_context(
            ReqContext::from(local, peer),
            async move {
                debug!("New connection from client");

                // Set read & write timeouts for processing the message.
                if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(3))) {
                    let _ = alert(&mut stream, tls::AlertDescription::InternalError);
                    error!("Could not set a read timeout on TCP stream: {e}");
                    return;
                }
                if let Err(e) = stream.set_write_timeout(Some(Duration::from_secs(3))) {
                    let _ = alert(&mut stream, tls::AlertDescription::InternalError);
                    error!("Could not set a write timeout on TCP stream: {e}");
                    return;
                }

                if let Err(e) = handle_stream(config, stream).await {
                    error!("{e}");
                }
            },
        ));
    }

    Ok(())
}

#[inline(always)]
pub(super) async fn proxy(client: TcpStream, backend: TcpStream) -> Result<()> {
    // Send keepalive to both the client and the backend.
    let keep_alive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(60));
    socket2::SockRef::from(&client).set_tcp_keepalive(&keep_alive)?;
    socket2::SockRef::from(&backend).set_tcp_keepalive(&keep_alive)?;

    // All good, proxy the rest of the connection.
    client.set_nonblocking(true)?;
    backend.set_nonblocking(true)?;
    let mut client = tokio::net::TcpStream::from_std(client)?;
    let mut backend = tokio::net::TcpStream::from_std(backend)?;

    // Move data between backend & client until connections are closed.
    debug!("Starting proxying the connection");
    let _ = zc::copy_bidirectional(&mut backend, &mut client).await;
    debug!("Connection shut down");

    Ok(())
}
