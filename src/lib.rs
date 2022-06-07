/*
 * Copyright 2019 fsyncd, Berlin, Germany.
 * Additional material Copyright the Rust project and it's contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Virtio socket support for Rust.

use libc::{
    accept4, ioctl, sa_family_t, sockaddr, sockaddr_vm, socklen_t, suseconds_t, timeval, AF_VSOCK,
    FIONBIO, SOCK_CLOEXEC,
};
use nix::{
    ioctl_read_bad,
    sys::socket::{
        self, bind, connect, getpeername, getsockname, listen, recv, send, shutdown, socket,
        sockopt::{ReceiveTimeout, SendTimeout, SocketError},
        AddressFamily, GetSockOpt, MsgFlags, SetSockOpt, SockFlag, SockType,
    },
    unistd::close,
};
use std::fs::File;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::mem::{self, size_of};
use std::net::Shutdown;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::time::Duration;

pub use libc::{VMADDR_CID_ANY, VMADDR_CID_HOST, VMADDR_CID_HYPERVISOR, VMADDR_CID_LOCAL};
pub use nix::sys::socket::{SockaddrLike, VsockAddr};

fn new_socket() -> Result<RawFd> {
    Ok(socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?)
}

/// An iterator that infinitely accepts connections on a VsockListener.
#[derive(Debug)]
pub struct Incoming<'a> {
    listener: &'a VsockListener,
}

impl<'a> Iterator for Incoming<'a> {
    type Item = Result<VsockStream>;

    fn next(&mut self) -> Option<Result<VsockStream>> {
        Some(self.listener.accept().map(|p| p.0))
    }
}

/// A virtio socket server, listening for connections.
#[derive(Debug, Clone)]
pub struct VsockListener {
    socket: RawFd,
}

impl VsockListener {
    /// Create a new VsockListener which is bound and listening on the socket address.
    pub fn bind(addr: &impl SockaddrLike) -> Result<Self> {
        if addr.family() != Some(AddressFamily::Vsock) {
            return Err(Error::new(
                ErrorKind::Other,
                "requires a virtio socket address",
            ));
        }

        let socket = new_socket()?;

        bind(socket, addr)?;

        // rust stdlib uses a 128 connection backlog
        listen(socket, 128)?;

        Ok(Self { socket })
    }

    /// Create a new VsockListener with specified cid and port.
    pub fn bind_with_cid_port(cid: u32, port: u32) -> Result<VsockListener> {
        Self::bind(&VsockAddr::new(cid, port))
    }

    /// The local socket address of the listener.
    pub fn local_addr(&self) -> Result<VsockAddr> {
        Ok(getsockname(self.socket)?)
    }

    /// Create a new independently owned handle to the underlying socket.
    pub fn try_clone(&self) -> Result<Self> {
        Ok(self.clone())
    }

    /// Accept a new incoming connection from this listener.
    pub fn accept(&self) -> Result<(VsockStream, VsockAddr)> {
        let mut vsock_addr = sockaddr_vm {
            svm_family: AF_VSOCK as sa_family_t,
            svm_reserved1: 0,
            svm_port: 0,
            svm_cid: 0,
            svm_zero: [0u8; 4],
        };
        let mut vsock_addr_len = size_of::<sockaddr_vm>() as socklen_t;
        let socket = unsafe {
            accept4(
                self.socket,
                &mut vsock_addr as *mut _ as *mut sockaddr,
                &mut vsock_addr_len,
                SOCK_CLOEXEC,
            )
        };
        if socket < 0 {
            Err(Error::last_os_error())
        } else {
            Ok((
                unsafe { VsockStream::from_raw_fd(socket as RawFd) },
                VsockAddr::new(vsock_addr.svm_cid, vsock_addr.svm_port),
            ))
        }
    }

    /// An iterator over the connections being received on this listener.
    pub fn incoming(&self) -> Incoming {
        Incoming { listener: self }
    }

    /// Retrieve the latest error associated with the underlying socket.
    pub fn take_error(&self) -> Result<Option<Error>> {
        let error = SocketError.get(self.socket)?;
        Ok(if error == 0 {
            None
        } else {
            Some(Error::from_raw_os_error(error))
        })
    }

    /// Move this stream in and out of nonblocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        let mut nonblocking: i32 = if nonblocking { 1 } else { 0 };
        if unsafe { ioctl(self.socket, FIONBIO, &mut nonblocking) } < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl AsRawFd for VsockListener {
    fn as_raw_fd(&self) -> RawFd {
        self.socket
    }
}

impl FromRawFd for VsockListener {
    unsafe fn from_raw_fd(socket: RawFd) -> Self {
        Self { socket }
    }
}

impl IntoRawFd for VsockListener {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.socket;
        mem::forget(self);
        fd
    }
}

impl Drop for VsockListener {
    fn drop(&mut self) {
        let _ = close(self.socket);
    }
}

/// A virtio stream between a local and a remote socket.
#[derive(Debug, Clone)]
pub struct VsockStream {
    socket: RawFd,
}

impl VsockStream {
    /// Open a connection to a remote host.
    pub fn connect(addr: &impl SockaddrLike) -> Result<Self> {
        if addr.family() != Some(AddressFamily::Vsock) {
            return Err(Error::new(
                ErrorKind::Other,
                "requires a virtio socket address",
            ));
        }

        let sock = new_socket()?;
        connect(sock, addr)?;
        Ok(unsafe { Self::from_raw_fd(sock) })
    }

    /// Open a connection to a remote host with specified cid and port.
    pub fn connect_with_cid_port(cid: u32, port: u32) -> Result<Self> {
        Self::connect(&VsockAddr::new(cid, port))
    }

    /// Virtio socket address of the remote peer associated with this connection.
    pub fn peer_addr(&self) -> Result<VsockAddr> {
        Ok(getpeername(self.socket)?)
    }

    /// Virtio socket address of the local address associated with this connection.
    pub fn local_addr(&self) -> Result<VsockAddr> {
        Ok(getsockname(self.socket)?)
    }

    /// Shutdown the read, write, or both halves of this connection.
    pub fn shutdown(&self, how: Shutdown) -> Result<()> {
        let how = match how {
            Shutdown::Write => socket::Shutdown::Write,
            Shutdown::Read => socket::Shutdown::Read,
            Shutdown::Both => socket::Shutdown::Both,
        };
        Ok(shutdown(self.socket, how)?)
    }

    /// Create a new independently owned handle to the underlying socket.
    pub fn try_clone(&self) -> Result<Self> {
        Ok(self.clone())
    }

    /// Set the timeout on read operations.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> Result<()> {
        let timeout = Self::timeval_from_duration(dur)?.into();
        Ok(SendTimeout.set(self.socket, &timeout)?)
    }

    /// Set the timeout on write operations.
    pub fn set_write_timeout(&self, dur: Option<Duration>) -> Result<()> {
        let timeout = Self::timeval_from_duration(dur)?.into();
        Ok(ReceiveTimeout.set(self.socket, &timeout)?)
    }

    /// Retrieve the latest error associated with the underlying socket.
    pub fn take_error(&self) -> Result<Option<Error>> {
        let error = SocketError.get(self.socket)?;
        Ok(if error == 0 {
            None
        } else {
            Some(Error::from_raw_os_error(error))
        })
    }

    /// Move this stream in and out of nonblocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        let mut nonblocking: i32 = if nonblocking { 1 } else { 0 };
        if unsafe { ioctl(self.socket, FIONBIO, &mut nonblocking) } < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn timeval_from_duration(dur: Option<Duration>) -> Result<timeval> {
        match dur {
            Some(dur) => {
                if dur.as_secs() == 0 && dur.subsec_nanos() == 0 {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "cannot set a zero duration timeout",
                    ));
                }

                // https://github.com/rust-lang/libc/issues/1848
                #[cfg_attr(target_env = "musl", allow(deprecated))]
                let secs = if dur.as_secs() > libc::time_t::max_value() as u64 {
                    libc::time_t::max_value()
                } else {
                    dur.as_secs() as libc::time_t
                };
                let mut timeout = timeval {
                    tv_sec: secs,
                    tv_usec: i64::from(dur.subsec_micros()) as suseconds_t,
                };
                if timeout.tv_sec == 0 && timeout.tv_usec == 0 {
                    timeout.tv_usec = 1;
                }
                Ok(timeout)
            }
            None => Ok(timeval {
                tv_sec: 0,
                tv_usec: 0,
            }),
        }
    }
}

impl Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        <&Self>::read(&mut &*self, buf)
    }
}

impl Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        <&Self>::write(&mut &*self, buf)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Read for &VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        Ok(recv(self.socket, buf, MsgFlags::empty())?)
    }
}

impl Write for &VsockStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        Ok(send(self.socket, buf, MsgFlags::MSG_NOSIGNAL)?)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl AsRawFd for VsockStream {
    fn as_raw_fd(&self) -> RawFd {
        self.socket
    }
}

impl FromRawFd for VsockStream {
    unsafe fn from_raw_fd(socket: RawFd) -> Self {
        Self { socket }
    }
}

impl IntoRawFd for VsockStream {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.socket;
        mem::forget(self);
        fd
    }
}

impl Drop for VsockStream {
    fn drop(&mut self) {
        let _ = close(self.socket);
    }
}

const IOCTL_VM_SOCKETS_GET_LOCAL_CID: usize = 0x7b9;
ioctl_read_bad!(
    vm_sockets_get_local_cid,
    IOCTL_VM_SOCKETS_GET_LOCAL_CID,
    u32
);

/// Gets the CID of the local machine.
///
/// Note that when calling [`VsockListener::bind`], you should generally use [`VMADDR_CID_ANY`]
/// instead, and for making a loopback connection you should use [`VMADDR_CID_LOCAL`].
pub fn get_local_cid() -> Result<u32> {
    let f = File::open("/dev/vsock")?;
    let mut cid = 0;
    // SAFETY: the kernel only modifies the given u32 integer.
    unsafe { vm_sockets_get_local_cid(f.as_raw_fd(), &mut cid) }?;
    Ok(cid)
}
