use std::{cell::RefCell, future::Future, net::SocketAddr};

use anyhow::Result;
use tokio::task::futures::TaskLocalFuture;

tokio::task_local! {
    pub(crate) static REQ_CONTEXT: RefCell<ReqContext>;
}

/// Request context, embedding per-request information in tokio tasks.
pub(crate) struct ReqContext {
    /// Local IP & port.
    pub(crate) local: SocketAddr,
    /// Peer IP & port.
    pub(crate) peer: SocketAddr,
    /// Hostname requested. Can be None early in the processing.
    pub(crate) hostname: Option<String>,
}

impl ReqContext {
    /// Initialize a new request context given local & peer information.
    pub(crate) fn from(local: SocketAddr, peer: SocketAddr) -> RefCell<Self> {
        RefCell::new(Self {
            local,
            peer,
            hostname: None,
        })
    }

    /// Set the context hostname.
    fn set_hostname(&mut self, hostname: String) {
        self.hostname = Some(hostname)
    }
}

/// Run a future with a request context.
pub(crate) fn with_req_context<F: Future>(
    context: RefCell<ReqContext>,
    f: F,
) -> TaskLocalFuture<RefCell<ReqContext>, F> {
    REQ_CONTEXT.scope(context, f)
}

/// Set the current context hostname. Can fail if not context is defined.
pub(crate) fn set_hostname(hostname: &str) -> Result<()> {
    REQ_CONTEXT.try_with(|context| context.borrow_mut().set_hostname(hostname.to_string()))?;
    Ok(())
}

/// Returns the local address associated with the context.
pub(crate) fn local_addr() -> Result<SocketAddr> {
    Ok(REQ_CONTEXT.try_with(|context| -> SocketAddr {
        let context = context.borrow();
        context.local
    })?)
}

/// Returns the peer address associated with the context.
pub(crate) fn peer_addr() -> Result<SocketAddr> {
    Ok(REQ_CONTEXT.try_with(|context| -> SocketAddr {
        let context = context.borrow();
        context.peer
    })?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context() {
        let local = "[1111:1::42]:10443".parse().unwrap();
        let peer = "[1337:42::700]:12345".parse().unwrap();

        with_req_context(ReqContext::from(local, peer), async {
            REQ_CONTEXT.with(|context| {
                let context = context.borrow();
                assert_eq!(context.local, "[1111:1::42]:10443".parse().unwrap());
                assert_eq!(context.peer, "[1337:42::700]:12345".parse().unwrap());
                assert_eq!(context.hostname, None);
            });
            assert!(set_hostname("example.net").is_ok());
            REQ_CONTEXT.with(|context| {
                let context = context.borrow();
                assert_eq!(context.hostname, Some("example.net".to_string()));
            });
        });

        assert!(REQ_CONTEXT.try_with(|_| {}).is_err());
        assert!(set_hostname("example.net").is_err());
    }
}
