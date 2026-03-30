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
    accept, fcntl, ioctl, sa_family_t, sockaddr, sockaddr_vm, socklen_t, timeval, AF_VSOCK,
    FD_CLOEXEC, FIONBIO, F_SETFD,
};
use nix::{
    ioctl_read_bad,
    sys::{
        socket::{
            self, bind, connect, getpeername, getsockname, listen, recv, recvfrom, send, sendto,
            shutdown, socket,
            sockopt::{ReceiveTimeout, SendTimeout, SocketError},
            AddressFamily, Backlog, GetSockOpt, MsgFlags, SetSockOpt, SockFlag, SockType,
        },
        time::TimeVal,
    },
    unistd::close,
};
use std::mem::size_of;
use std::net::Shutdown;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::time::Duration;
use std::{fs::File, os::fd::OwnedFd};
use std::{
    io::{Error, ErrorKind, Read, Result, Write},
    os::fd::{AsFd, BorrowedFd},
};

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use libc::VMADDR_CID_LOCAL;
pub use libc::{VMADDR_CID_ANY, VMADDR_CID_HOST, VMADDR_CID_HYPERVISOR};
pub use nix::sys::socket::{SockaddrLike, VsockAddr};

fn new_socket(ty: SockType) -> Result<OwnedFd> {
    #[cfg(not(target_os = "macos"))]
    let flags = SockFlag::SOCK_CLOEXEC;
    #[cfg(target_os = "macos")]
    let flags = SockFlag::empty();
    Ok(socket(AddressFamily::Vsock, ty, flags, None)?)
}

fn default_send_msg_flags() -> MsgFlags {
    #[cfg(not(target_os = "macos"))]
    let flags = MsgFlags::MSG_NOSIGNAL;
    #[cfg(target_os = "macos")]
    let flags = MsgFlags::empty();
    flags
}

/// Internal helper to turn a [`Duration`] into a [`TimeVal`].
fn timeval_from_duration(dur: Option<Duration>) -> Result<TimeVal> {
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
            let secs = if dur.as_secs() > libc::time_t::MAX as u64 {
                libc::time_t::MAX
            } else {
                dur.as_secs() as libc::time_t
            };
            #[cfg_attr(target_env = "musl", allow(deprecated))]
            let mut timeout = timeval {
                tv_sec: secs,
                tv_usec: i64::from(dur.subsec_micros()) as libc::suseconds_t,
            };
            if timeout.tv_sec == 0 && timeout.tv_usec == 0 {
                timeout.tv_usec = 1;
            }
            Ok(timeout.into())
        }
        None => Ok(TimeVal::new(0, 0)),
    }
}

/// An iterator that infinitely accepts connections on a VsockListener.
#[derive(Debug)]
pub struct Incoming<'a> {
    listener: &'a VsockListener,
}

impl Iterator for Incoming<'_> {
    type Item = Result<VsockStream>;

    fn next(&mut self) -> Option<Result<VsockStream>> {
        Some(self.listener.accept().map(|p| p.0))
    }
}

/// A virtio socket server, listening for connections.
#[derive(Debug)]
pub struct VsockListener {
    socket: OwnedFd,
}

impl VsockListener {
    /// Create a new VsockListener which is bound and listening on the socket address.
    pub fn bind(addr: &impl SockaddrLike) -> Result<Self> {
        if addr.family() != Some(AddressFamily::Vsock) {
            return Err(Error::other("requires a virtio socket address"));
        }

        let socket = new_socket(SockType::Stream)?;

        bind(socket.as_raw_fd(), addr)?;

        // rust stdlib uses a 128 connection backlog
        listen(&socket, Backlog::new(128).unwrap_or(Backlog::MAXCONN))?;

        Ok(Self { socket })
    }

    /// Create a new VsockListener with specified cid and port.
    pub fn bind_with_cid_port(cid: u32, port: u32) -> Result<VsockListener> {
        Self::bind(&VsockAddr::new(cid, port))
    }

    /// The local socket address of the listener.
    pub fn local_addr(&self) -> Result<VsockAddr> {
        Ok(getsockname(self.socket.as_raw_fd())?)
    }

    /// Create a new independently owned handle to the underlying socket.
    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            socket: self.socket.try_clone()?,
        })
    }

    /// Accept a new incoming connection from this listener.
    pub fn accept(&self) -> Result<(VsockStream, VsockAddr)> {
        let mut vsock_addr = sockaddr_vm {
            svm_family: AF_VSOCK as sa_family_t,
            svm_reserved1: 0,
            svm_port: 0,
            svm_cid: 0,
            #[cfg(not(target_os = "macos"))]
            svm_zero: [0u8; 4],
            #[cfg(target_os = "macos")]
            svm_len: size_of::<sockaddr_vm>() as u8,
        };
        let mut vsock_addr_len = size_of::<sockaddr_vm>() as socklen_t;
        let socket = unsafe {
            accept(
                self.socket.as_raw_fd(),
                &mut vsock_addr as *mut _ as *mut sockaddr,
                &mut vsock_addr_len,
            )
        };
        if socket < 0 {
            return Err(Error::last_os_error());
        }
        if unsafe { fcntl(socket, F_SETFD, FD_CLOEXEC) } < 0 {
            close(socket)?;
            Err(Error::last_os_error())
        } else {
            Ok((
                unsafe { VsockStream::from_raw_fd(socket as RawFd) },
                VsockAddr::new(vsock_addr.svm_cid, vsock_addr.svm_port),
            ))
        }
    }

    /// An iterator over the connections being received on this listener.
    pub fn incoming(&self) -> Incoming<'_> {
        Incoming { listener: self }
    }

    /// Retrieve the latest error associated with the underlying socket.
    pub fn take_error(&self) -> Result<Option<Error>> {
        let error = SocketError.get(&self.socket)?;
        Ok(if error == 0 {
            None
        } else {
            Some(Error::from_raw_os_error(error))
        })
    }

    /// Move this stream in and out of nonblocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        let mut nonblocking: i32 = if nonblocking { 1 } else { 0 };
        if unsafe { ioctl(self.socket.as_raw_fd(), FIONBIO, &mut nonblocking) } < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl AsRawFd for VsockListener {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

impl AsFd for VsockListener {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

impl FromRawFd for VsockListener {
    unsafe fn from_raw_fd(socket: RawFd) -> Self {
        Self {
            socket: OwnedFd::from_raw_fd(socket),
        }
    }
}

impl IntoRawFd for VsockListener {
    fn into_raw_fd(self) -> RawFd {
        self.socket.into_raw_fd()
    }
}

impl From<VsockListener> for OwnedFd {
    fn from(value: VsockListener) -> Self {
        value.socket
    }
}

impl From<OwnedFd> for VsockListener {
    fn from(socket: OwnedFd) -> Self {
        Self { socket }
    }
}

/// A virtio sequential packet socket between a local and a remote host.
///
/// This is the vsock equivalent of [`std::net::UdpSocket`].
#[derive(Debug)]
pub struct VsockSocket {
    socket: OwnedFd,
}

impl VsockSocket {
    /// Bind to an address and listen for connections.
    ///
    /// Analogous to [`std::net::UdpSocket::bind`]
    pub fn bind<A: SockaddrLike>(addr: &A) -> Result<Self> {
        if addr.family() != Some(AddressFamily::Vsock) {
            return Err(Error::other("requires a virtio socket address"));
        }

        let socket = new_socket(SockType::Datagram)?;

        bind(socket.as_raw_fd(), addr)?;

        Ok(Self { socket })
    }

    /// Bind to a specified cid and port and listen for connections.
    pub fn bind_with_cid_port(cid: u32, port: u32) -> Result<Self> {
        Self::bind(&VsockAddr::new(cid, port))
    }

    /// Receive a message from a remote host.
    ///
    /// Analogous to [`std::net::UdpSocket::recv_from`]
    ///
    /// # Returns
    ///
    /// The number of bytes read and the address of the remote host.
    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, VsockAddr)> {
        recvfrom(self.socket.as_raw_fd(), buf)
            // UNWRAP SAFETY: recvfrom should always return peer address when SockType == SockType::Datagram
            .map(|(size, addr)| (size, addr.expect("recv_from didn't return peer address")))
            .map_err(nix::Error::into)
    }

    /// Send a message to a remote host.
    ///
    /// Analogous to [`std::net::UdpSocket::send_to`]
    pub fn send_to<A: SockaddrLike>(&self, buf: &[u8], addr: &A) -> Result<usize> {
        sendto(self.socket.as_raw_fd(), buf, addr, default_send_msg_flags())
            .map_err(nix::Error::into)
    }

    /// Send a message to a remote host with specified cid and port.
    pub fn send_to_with_cid_port(&self, buf: &[u8], cid: u32, port: u32) -> Result<usize> {
        self.send_to(buf, &VsockAddr::new(cid, port))
    }

    /// Virtio socket address of the remote peer associated with this connection.
    pub fn peer_addr(&self) -> Result<VsockAddr> {
        Ok(getpeername(self.socket.as_raw_fd())?)
    }

    /// Virtio socket address of the local address associated with this connection.
    pub fn local_addr(&self) -> Result<VsockAddr> {
        Ok(getsockname(self.socket.as_raw_fd())?)
    }

    /// Create a new independently owned handle to the underlying socket.
    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            socket: self.socket.try_clone()?,
        })
    }

    /// Set the timeout on read operations.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> Result<()> {
        let timeout = timeval_from_duration(dur)?;
        Ok(ReceiveTimeout.set(&self.socket, &timeout)?)
    }

    /// Set the timeout on write operations.
    pub fn set_write_timeout(&self, dur: Option<Duration>) -> Result<()> {
        let timeout = timeval_from_duration(dur)?;
        Ok(SendTimeout.set(&self.socket, &timeout)?)
    }

    /// Retrieve the latest error associated with the underlying socket.
    pub fn take_error(&self) -> Result<Option<Error>> {
        let error = SocketError.get(&self.socket)?;
        Ok(if error == 0 {
            None
        } else {
            Some(Error::from_raw_os_error(error))
        })
    }

    /// Open a connection to a remote host (you need to bind to an address with [`Self::bind`]
    /// first).
    ///
    /// Allows you to send and receive messages from this host directly through [`Self::send`] and
    /// [`Self::recv`].
    ///
    /// Analogous to [`std::net::UdpSocket::connect`]
    pub fn connect<A: SockaddrLike>(&self, addr: &A) -> Result<()> {
        if addr.family() != Some(AddressFamily::Vsock) {
            return Err(Error::other("requires a virtio socket address"));
        }

        connect(self.socket.as_raw_fd(), addr).map_err(nix::Error::into)
    }

    /// Open a connection to a remote host with specified cid and port (you need to bind to an
    /// address with [`Self::bind`] first).
    ///
    /// Allows you to send and receive messages from this host directly through [`Self::send`] and
    /// [`Self::recv`].
    pub fn connect_with_cid_port(&self, cid: u32, port: u32) -> Result<()> {
        self.connect(&VsockAddr::new(cid, port))
    }

    /// Send data to the connected remote host.
    ///
    /// Analogous to [`std::net::UdpSocket::send`]
    pub fn send(&self, buf: &[u8]) -> Result<usize> {
        send(self.socket.as_raw_fd(), buf, default_send_msg_flags()).map_err(nix::Error::into)
    }

    /// Receive data from the connected remote host.
    ///
    /// Analogous to [`std::net::UdpSocket::recv`]
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        recv(self.socket.as_raw_fd(), buf, MsgFlags::empty()).map_err(nix::Error::into)
    }

    /// Move this stream in and out of nonblocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        let mut nonblocking: i32 = if nonblocking { 1 } else { 0 };
        if unsafe { ioctl(self.socket.as_raw_fd(), FIONBIO, &mut nonblocking) } < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl AsFd for VsockSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

impl AsRawFd for VsockSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

impl FromRawFd for VsockSocket {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self {
            socket: OwnedFd::from_raw_fd(fd),
        }
    }
}

impl IntoRawFd for VsockSocket {
    fn into_raw_fd(self) -> RawFd {
        self.socket.into_raw_fd()
    }
}

impl From<VsockSocket> for OwnedFd {
    fn from(value: VsockSocket) -> Self {
        value.socket
    }
}

impl From<OwnedFd> for VsockSocket {
    fn from(socket: OwnedFd) -> Self {
        Self { socket }
    }
}

/// A virtio stream between a local and a remote socket.
///
/// This is the vsock equivalent of [`std::net::TcpStream`].
#[derive(Debug)]
pub struct VsockStream {
    socket: OwnedFd,
}

impl VsockStream {
    /// Open a connection to a remote host.
    pub fn connect(addr: &impl SockaddrLike) -> Result<Self> {
        if addr.family() != Some(AddressFamily::Vsock) {
            return Err(Error::other("requires a virtio socket address"));
        }

        let socket = new_socket(SockType::Stream)?;
        connect(socket.as_raw_fd(), addr)?;
        Ok(Self { socket })
    }

    /// Open a connection to a remote host with specified cid and port.
    pub fn connect_with_cid_port(cid: u32, port: u32) -> Result<Self> {
        Self::connect(&VsockAddr::new(cid, port))
    }

    /// Virtio socket address of the remote peer associated with this connection.
    pub fn peer_addr(&self) -> Result<VsockAddr> {
        Ok(getpeername(self.socket.as_raw_fd())?)
    }

    /// Virtio socket address of the local address associated with this connection.
    pub fn local_addr(&self) -> Result<VsockAddr> {
        Ok(getsockname(self.socket.as_raw_fd())?)
    }

    /// Shutdown the read, write, or both halves of this connection.
    pub fn shutdown(&self, how: Shutdown) -> Result<()> {
        let how = match how {
            Shutdown::Write => socket::Shutdown::Write,
            Shutdown::Read => socket::Shutdown::Read,
            Shutdown::Both => socket::Shutdown::Both,
        };
        Ok(shutdown(self.socket.as_raw_fd(), how)?)
    }

    /// Create a new independently owned handle to the underlying socket.
    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            socket: self.socket.try_clone()?,
        })
    }

    /// Set the timeout on read operations.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> Result<()> {
        let timeout = timeval_from_duration(dur)?;
        Ok(ReceiveTimeout.set(&self.socket, &timeout)?)
    }

    /// Set the timeout on write operations.
    pub fn set_write_timeout(&self, dur: Option<Duration>) -> Result<()> {
        let timeout = timeval_from_duration(dur)?;
        Ok(SendTimeout.set(&self.socket, &timeout)?)
    }

    /// Retrieve the latest error associated with the underlying socket.
    pub fn take_error(&self) -> Result<Option<Error>> {
        let error = SocketError.get(&self.socket)?;
        Ok(if error == 0 {
            None
        } else {
            Some(Error::from_raw_os_error(error))
        })
    }

    /// Move this stream in and out of nonblocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        let mut nonblocking: i32 = if nonblocking { 1 } else { 0 };
        if unsafe { ioctl(self.socket.as_raw_fd(), FIONBIO, &mut nonblocking) } < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
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
        Ok(recv(self.socket.as_raw_fd(), buf, MsgFlags::empty())?)
    }
}

impl Write for &VsockStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        Ok(send(
            self.socket.as_raw_fd(),
            buf,
            default_send_msg_flags(),
        )?)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl AsRawFd for VsockStream {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

impl AsFd for VsockStream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

impl FromRawFd for VsockStream {
    unsafe fn from_raw_fd(socket: RawFd) -> Self {
        Self {
            socket: OwnedFd::from_raw_fd(socket),
        }
    }
}

impl IntoRawFd for VsockStream {
    fn into_raw_fd(self) -> RawFd {
        self.socket.into_raw_fd()
    }
}

impl From<VsockStream> for OwnedFd {
    fn from(value: VsockStream) -> Self {
        value.socket
    }
}

impl From<OwnedFd> for VsockStream {
    fn from(socket: OwnedFd) -> Self {
        Self { socket }
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
