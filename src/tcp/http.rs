use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
};

use anyhow::{Result, bail};

use crate::{config::Config, context, http, reader::ReaderBuf};

/// Handle TCP/HTTP connections.
pub(crate) async fn handle_stream(config: Arc<Config>, stream: TcpStream) -> Result<()> {
    // 8KB is the limit size on many web servers.
    try_redirect(
        &config,
        &context::peer_addr()?,
        ReaderBuf::with_capacity(8192, stream),
    )
}

#[inline(always)]
fn try_redirect<R>(config: &Config, client: &SocketAddr, mut rb: ReaderBuf<R>) -> Result<()>
where
    R: Read + Write,
{
    // First check if the connection looks like an HTTP one. We only need 5
    // bytes for `http::is_http`.
    rb.read(5)?;
    if !http::is_http(&rb) {
        bail!("Not an HTTP request");
    }

    // Looks like an HTTP request, try redirecting it.
    http::try_redirect(config, client, &mut rb)
}
