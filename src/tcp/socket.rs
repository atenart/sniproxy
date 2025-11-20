use std::{
    io,
    mem::MaybeUninit,
    net::SocketAddrV6,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
    time::Instant,
};

pub(crate) struct Socket6(OwnedFd);

impl Socket6 {
    pub(crate) fn new() -> io::Result<Self> {
        // SAFETY: libc socket call
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is valid and from libc::socket
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        Ok(Self(fd))
    }

    pub(crate) fn setsockopt<T>(
        &mut self,
        level: libc::c_int,
        option_name: libc::c_int,
        option_value: T,
    ) -> io::Result<()> {
        let ret = unsafe {
            libc::setsockopt(
                self.as_raw_fd(),
                level,
                option_name,
                (&raw const option_value).cast::<libc::c_void>(),
                std::mem::size_of::<T>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn getsockopt<T: Copy>(
        &mut self,
        level: libc::c_int,
        option_name: libc::c_int,
    ) -> io::Result<T> {
        let mut option_value = MaybeUninit::zeroed();
        let mut option_len = size_of::<T>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                self.as_raw_fd(),
                level,
                option_name,
                option_value.as_mut_ptr() as *mut _,
                &mut option_len,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { option_value.assume_init() })
    }

    pub(crate) fn bind(&mut self, addr: libc::sockaddr_in6) -> io::Result<()> {
        let ret = unsafe {
            libc::bind(
                self.as_raw_fd(),
                (&raw const addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        let mut nonblocking = nonblocking as libc::c_int;
        let ret = unsafe { libc::ioctl(self.as_raw_fd(), libc::FIONBIO, &mut nonblocking) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn take_error(&mut self) -> io::Result<Option<io::Error>> {
        let raw: libc::c_int = self.getsockopt(libc::SOL_SOCKET, libc::SO_ERROR)?;
        if raw == 0 {
            Ok(None)
        } else {
            Ok(Some(io::Error::from_raw_os_error(raw as i32)))
        }
    }

    pub(crate) fn connect_timeout(
        &mut self,
        addr: &SocketAddrV6,
        timeout: std::time::Duration,
    ) -> std::io::Result<()> {
        let addr = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as _,
            sin6_flowinfo: addr.flowinfo(),
            sin6_port: addr.port().to_be(),
            sin6_addr: libc::in6_addr {
                s6_addr: addr.ip().octets(),
            },
            sin6_scope_id: addr.scope_id(),
        };

        self.set_nonblocking(true)?;
        let ret = unsafe {
            libc::connect(
                self.as_raw_fd(),
                (&raw const addr) as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        };
        let ret = if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        };
        self.set_nonblocking(false)?;

        match ret {
            Ok(_) => return Ok(()),
            Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => return Err(e),
        }

        let mut pollfd = libc::pollfd {
            fd: self.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };

        if timeout.as_secs() == 0 && timeout.subsec_nanos() == 0 {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "Zero timeout"));
        }

        let start = Instant::now();

        loop {
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "Timeout reached"));
            }

            let timeout = timeout - elapsed;
            let mut timeout = timeout
                .as_secs()
                .saturating_mul(1_000)
                .saturating_add(timeout.subsec_nanos() as u64 / 1_000_000);
            if timeout == 0 {
                timeout = 1;
            }

            let timeout = std::cmp::min(timeout, libc::c_int::MAX as u64) as libc::c_int;

            match unsafe { libc::poll(&mut pollfd, 1, timeout) } {
                -1 => {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error().unwrap() != libc::EINTR as _ {
                        return Err(err);
                    }
                }
                0 => {}
                _ => {
                    if pollfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                        let e = self.take_error()?.unwrap_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::ResourceBusy,
                                "no error set after POLLHUP",
                            )
                        });
                        return Err(e);
                    }

                    return Ok(());
                }
            }
        }
    }
}

impl AsRawFd for Socket6 {
    #[inline]
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.0.as_raw_fd()
    }
}

impl IntoRawFd for Socket6 {
    #[inline]
    fn into_raw_fd(self) -> std::os::unix::prelude::RawFd {
        self.0.into_raw_fd()
    }
}
