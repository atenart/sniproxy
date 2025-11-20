use std::{
    future::poll_fn,
    io::{self, Error},
    mem,
    os::fd::{AsRawFd, RawFd},
    pin::Pin,
    ptr,
    task::{Context, Poll, ready},
};

use anyhow::{Result, anyhow, bail};
use tokio::io::AsyncWriteExt;

// Use 1M pipe size as this is the default max pipe buffer size
// (see /proc/sys/fs/pipe-max-size).
const PIPE_SIZE: usize = 1 << 20;

/// Bidirectional copy between two ZcAsyncIo enabled-types, in a zero-copy
/// fashion.
pub(crate) async fn copy_bidirectional<T>(a: &mut T, b: &mut T) -> Result<(usize, usize)>
where
    T: ZcAsyncIo,
{
    let mut ab = Splice::new()?;
    let mut ba = Splice::new()?;

    let ret = poll_fn(|ctx| {
        // Do not wait for both ends to gracefully shutdown.
        match (ab.process(ctx, a, b)?, ba.process(ctx, b, a)?) {
            (Poll::Ready(a), Poll::Ready(b)) => Poll::Ready(Ok((a, b))),
            (Poll::Ready(a), Poll::Pending) => Poll::Ready(Ok((a, 0))),
            (Poll::Pending, Poll::Ready(b)) => Poll::Ready(Ok((0, b))),
            _ => Poll::Pending,
        }
    })
    .await;

    if ret.is_err() {
        // In case the copy did not returned cleanly, make sure both sides are
        // closed.
        let _ = a.shutdown().await;
        let _ = b.shutdown().await;
    }
    ret
}

/// Trait to access async io operations. Direct 1:1 mapping to what some tokio
/// types provide.
pub(crate) trait ZcAsyncIo:
    Unpin + AsRawFd + tokio::io::AsyncRead + tokio::io::AsyncWrite
{
    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
    fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
    fn try_io<R>(
        &self,
        interest: tokio::io::Interest,
        f: impl FnOnce() -> io::Result<R>,
    ) -> io::Result<R>;
    async fn shutdown(&mut self) -> io::Result<()>;
}

macro_rules! zero_copy {
    ($target: ty) => {
        impl ZcAsyncIo for $target {
            #[inline(always)]
            fn poll_read_ready(&self, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.poll_read_ready(ctx)
            }
            #[inline(always)]
            fn poll_write_ready(&self, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.poll_write_ready(ctx)
            }
            #[inline(always)]
            fn try_io<R>(
                &self,
                interest: tokio::io::Interest,
                f: impl FnOnce() -> io::Result<R>,
            ) -> io::Result<R> {
                self.try_io(interest, f)
            }
            #[inline(always)]
            async fn shutdown(&mut self) -> io::Result<()> {
                AsyncWriteExt::shutdown(self).await
            }
        }
    };
}
zero_copy!(tokio::net::TcpStream);

/// Splice represents a stateful zero-copy between two file descriptors, under
/// the hood using pipe2(2) and splice(2).
enum Splice {
    /// Move state: data is being moved from one fd to the other.
    Move(SpliceMove),
    /// Shutting down state: copy is over, some data might need to be flushed.
    ShuttingDown(usize),
    /// Done: all data was moved and was flushed, no further action can be
    /// taken.
    Done,
}

impl Splice {
    fn new() -> Result<Self> {
        Ok(Self::Move(SpliceMove {
            pipe: Pipe::new()?,
            processed: 0,
            in_pipe: 0,
            flush: false,
        }))
    }

    /// Calls internal logic depending on the current Splice state. This should
    /// be called for transferring data between fds and for all subsequent
    /// operations.
    fn process<T>(&mut self, ctx: &mut Context<'_>, src: &mut T, dst: &mut T) -> Poll<Result<usize>>
    where
        T: ZcAsyncIo,
    {
        loop {
            match self {
                Self::Move(r#move) => {
                    let processed = ready!(r#move.copy(ctx, src, dst))?;
                    *self = Self::ShuttingDown(processed);
                }
                Self::ShuttingDown(processed) => {
                    if let Err(e) = ready!(Pin::new(dst).poll_shutdown(ctx)) {
                        match e.kind() {
                            // Ignore error if the socket is already closed.
                            io::ErrorKind::NotConnected => (),
                            _ => return Poll::Ready(Err(e.into())),
                        }
                    }

                    let ret = Poll::Ready(Ok(*processed));
                    *self = Self::Done;
                    return ret;
                }
                Self::Done => return Poll::Ready(Err(anyhow!("Splice is in \"done\" state"))),
            }
        }
    }
}

/// Hold data for the Move state of Splice.
struct SpliceMove {
    pipe: Pipe,
    processed: usize,
    in_pipe: usize,
    flush: bool,
}

impl SpliceMove {
    fn copy<T>(&mut self, ctx: &mut Context<'_>, src: &mut T, dst: &mut T) -> Poll<Result<usize>>
    where
        T: ZcAsyncIo,
    {
        loop {
            while self.in_pipe == 0 {
                match src.poll_read_ready(ctx) {
                    Poll::Ready(ret) => ret,
                    Poll::Pending => {
                        // Flush in case stream is not ready for read because
                        // the other end of the connection is waiting for
                        // buffered data on our end.
                        if self.flush {
                            ready!(Pin::new(dst).poll_flush(ctx))?;
                            self.flush = false;
                        }

                        return Poll::Pending;
                    }
                }?;

                let ret = src.try_io(tokio::io::Interest::READABLE, || {
                    Self::splice(src.as_raw_fd(), self.pipe.write, PIPE_SIZE)
                });

                match ret {
                    Ok(0) => return Poll::Ready(Ok(self.processed)),
                    Ok(moved) => self.in_pipe = moved,
                    Err(e) => {
                        match e.kind() {
                            io::ErrorKind::WouldBlock => continue,
                            io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::BrokenPipe => return Poll::Ready(Ok(self.processed)),
                            _ => (),
                        }

                        return Poll::Ready(Err(e.into()));
                    }
                }
            }

            // Keep track of how much data we transferred.
            self.processed += self.in_pipe;

            // Transfer data from the pipe.
            while self.in_pipe > 0 {
                ready!(dst.poll_write_ready(ctx))?;

                let ret = dst.try_io(tokio::io::Interest::WRITABLE, || {
                    Self::splice(self.pipe.read, dst.as_raw_fd(), self.in_pipe)
                });

                match ret {
                    Ok(moved) => {
                        self.in_pipe -= moved;
                        self.flush = true;
                    }
                    Err(e) => {
                        match e.kind() {
                            io::ErrorKind::WouldBlock => continue,
                            io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::BrokenPipe => return Poll::Ready(Ok(self.processed)),
                            _ => (),
                        }

                        return Poll::Ready(Err(e.into()));
                    }
                }
            }
        }
    }

    fn splice(src: RawFd, dst: RawFd, size: usize) -> io::Result<usize> {
        loop {
            let ret = unsafe {
                libc::splice(
                    src,
                    ptr::null_mut::<libc::loff_t>(),
                    dst,
                    ptr::null_mut::<libc::loff_t>(),
                    size,
                    libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                )
            };

            // Convert the raw result to io::Result. Both EAGAIN and EWOULDBLOCK
            // are converted to io::ErrorKind::WouldBlock; this extremely
            // important because we might get called from tokio try_io helpers
            // which intercept io::ErrorKind::WouldBlock and acts on the socket
            // readiness accordingly.
            match ret {
                x if x < 0 => {
                    let err = Error::last_os_error();
                    match err.raw_os_error() {
                        Some(e) if e == libc::EINTR => continue,
                        _ => return Err(err),
                    }
                }
                _ => return Ok(ret as usize),
            }
        }
    }
}

/// Represents a Linux pipe, which can be used as an unidirectional channel for
/// moving data from or to an outside file descriptor.
struct Pipe {
    read: RawFd,
    write: RawFd,
}

impl Pipe {
    /// Creates a non-blocking Linux pipe, see pipe(2).
    fn new() -> Result<Self> {
        let mut pipefd = mem::MaybeUninit::<[libc::c_int; 2]>::uninit();

        let [read, write] = unsafe {
            if libc::pipe2(
                pipefd.as_mut_ptr() as *mut libc::c_int,
                libc::O_CLOEXEC | libc::O_NONBLOCK,
            ) < 0
            {
                bail!("Could not create pipe: {}", io::Error::last_os_error());
            }

            pipefd.assume_init()
        };

        unsafe {
            // Ignore errors here are not using the bigger buffer will work too,
            // just result in more syscalls.
            libc::fcntl(read, libc::F_SETPIPE_SZ, PIPE_SIZE);
        }

        Ok(Self { read, write })
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.read);
            libc::close(self.write);
        }
    }
}
