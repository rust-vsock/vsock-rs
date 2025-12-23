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

#![deny(unsafe_code)]

use rustix::{io, net};

use std::net::Shutdown;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::time::Duration;
use std::{fs::File, os::fd::OwnedFd};
use std::{
    io::{Error, Read, Result, Write},
    os::fd::{AsFd, BorrowedFd},
};

fn new_socket(ty: net::SocketType) -> Result<OwnedFd> {
    #[cfg(not(target_os = "macos"))]
    let flags = net::SocketFlags::CLOEXEC;
    #[cfg(target_os = "macos")]
    let flags = net::SocketFlags::empty();

    let socket = net::socket_with(net::AddressFamily::VSOCK, ty, flags, None)?;
    Ok(socket)
}

fn default_send_msg_flags() -> net::SendFlags {
    #[cfg(not(target_os = "macos"))]
    let flags = net::SendFlags::NOSIGNAL;
    #[cfg(target_os = "macos")]
    let flags = net::SendFlags::empty();
    flags
}

#[inline]
fn cvt_addr(addr: Option<net::SocketAddrAny>) -> Result<SocketAddr> {
    match addr {
        Some(addr) => Ok(SocketAddr::from_rustix(addr.try_into()?)),
        None => Err(Error::other("no address found")),
    }
}

/// CID to connect to any host.
pub const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
/// CID to connect to the hypervisor.
pub const VMADDR_CID_HYPERVISOR: u32 = 0;
/// CID to connect to the local host.
pub const VMADDR_CID_LOCAL: u32 = 1;
/// CID to connect to the host.
pub const VMADDR_CID_HOST: u32 = 2;
/// Connect to any port.
pub const VMADDR_PORT_ANY: u32 = 0xFFFFFFFF;

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

/// Socket address for a VSock.
#[derive(Debug, Copy, Clone)]
pub struct SocketAddr {
    cid: u32,
    port: u32,
}

impl SocketAddr {
    /// Create a new [`SocketAddr`].
    pub fn new(cid: u32, port: u32) -> Self {
        Self { cid, port }
    }

    /// Get the CID.
    pub fn cid(&self) -> u32 {
        self.cid
    }

    /// Set the CID.
    pub fn set_cid(&mut self, cid: u32) {
        self.cid = cid;
    }

    /// Get the port.
    pub fn port(&self) -> u32 {
        self.port
    }

    /// Set the port.
    pub fn set_port(&mut self, port: u32) {
        self.port = port;
    }

    /// Convert to the `rustix` address.
    fn to_rustix(self) -> net::vsock::SocketAddrVSock {
        net::vsock::SocketAddrVSock::new(self.cid, self.port)
    }

    /// Convert from the `rustix` address.
    fn from_rustix(r: net::vsock::SocketAddrVSock) -> Self {
        Self::new(r.cid(), r.port())
    }
}

/// A virtio socket server, listening for connections.
#[derive(Debug)]
pub struct VsockListener {
    socket: OwnedFd,
}

impl VsockListener {
    /// Create a new VsockListener which is bound and listening on the socket address.
    pub fn bind(addr: SocketAddr) -> Result<Self> {
        let socket = new_socket(net::SocketType::STREAM)?;

        net::bind(&socket, &addr.to_rustix())?;

        // rust stdlib uses a 128 connection backlog
        net::listen(&socket, 128)?;

        Ok(Self { socket })
    }

    /// Create a new VsockListener with specified cid and port.
    pub fn bind_with_cid_port(cid: u32, port: u32) -> Result<VsockListener> {
        Self::bind(SocketAddr::new(cid, port))
    }

    /// The local socket address of the listener.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        let addr = net::getsockname(&self.socket)?;
        Ok(SocketAddr::from_rustix(addr.try_into()?))
    }

    /// Create a new independently owned handle to the underlying socket.
    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            socket: self.socket.try_clone()?,
        })
    }

    /// Accept a new incoming connection from this listener.
    pub fn accept(&self) -> Result<(VsockStream, SocketAddr)> {
        let (stream, addr) = net::acceptfrom(&self.socket)?;
        let addr = cvt_addr(addr)?;

        io::fcntl_setfd(&stream, io::FdFlags::CLOEXEC)?;
        Ok((VsockStream { socket: stream }, addr))
    }

    /// An iterator over the connections being received on this listener.
    pub fn incoming(&self) -> Incoming<'_> {
        Incoming { listener: self }
    }

    /// Retrieve the latest error associated with the underlying socket.
    pub fn take_error(&self) -> Result<Option<Error>> {
        let error = net::sockopt::socket_error(&self.socket)?;
        match error {
            Ok(()) => Ok(None),
            Err(err) => Ok(Some(err.into())),
        }
    }

    /// Move this stream in and out of nonblocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        io::ioctl_fionbio(&self.socket, nonblocking)?;
        Ok(())
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
    #[allow(unsafe_code)]
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
    pub fn bind(addr: SocketAddr) -> Result<Self> {
        let socket = new_socket(net::SocketType::DGRAM)?;

        net::bind(&socket, &addr.to_rustix())?;

        Ok(Self { socket })
    }

    /// Bind to a specified cid and port and listen for connections.
    pub fn bind_with_cid_port(cid: u32, port: u32) -> Result<Self> {
        Self::bind(SocketAddr::new(cid, port))
    }

    /// Receive a message from a remote host.
    ///
    /// Analogous to [`std::net::UdpSocket::recv_from`]
    ///
    /// # Returns
    ///
    /// The number of bytes read and the address of the remote host.
    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let (recv, _, addr) = net::recvfrom(&self.socket, buf, net::RecvFlags::empty())?;
        let addr = cvt_addr(addr)?;

        Ok((recv, addr))
    }

    /// Send a message to a remote host.
    ///
    /// Analogous to [`std::net::UdpSocket::send_to`]
    pub fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        let sent = net::sendto(
            &self.socket,
            buf,
            default_send_msg_flags(),
            &addr.to_rustix(),
        )?;
        Ok(sent)
    }

    /// Send a message to a remote host with specified cid and port.
    pub fn send_to_with_cid_port(&self, buf: &[u8], cid: u32, port: u32) -> Result<usize> {
        self.send_to(buf, SocketAddr::new(cid, port))
    }

    /// Virtio socket address of the remote peer associated with this connection.
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        cvt_addr(net::getpeername(&self.socket)?)
    }

    /// Virtio socket address of the local address associated with this connection.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(SocketAddr::from_rustix(
            net::getsockname(&self.socket)?.try_into()?,
        ))
    }

    /// Create a new independently owned handle to the underlying socket.
    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            socket: self.socket.try_clone()?,
        })
    }

    /// Set the timeout on read operations.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> Result<()> {
        net::sockopt::set_socket_timeout(&self.socket, net::sockopt::Timeout::Recv, dur)?;
        Ok(())
    }

    /// Set the timeout on write operations.
    pub fn set_write_timeout(&self, dur: Option<Duration>) -> Result<()> {
        net::sockopt::set_socket_timeout(&self.socket, net::sockopt::Timeout::Send, dur)?;
        Ok(())
    }

    /// Retrieve the latest error associated with the underlying socket.
    pub fn take_error(&self) -> Result<Option<Error>> {
        let error = net::sockopt::socket_error(&self.socket)?;
        match error {
            Ok(()) => Ok(None),
            Err(err) => Ok(Some(err.into())),
        }
    }

    /// Open a connection to a remote host (you need to bind to an address with [`Self::bind`]
    /// first).
    ///
    /// Allows you to send and receive messages from this host directly through [`Self::send`] and
    /// [`Self::recv`].
    ///
    /// Analogous to [`std::net::UdpSocket::connect`]
    pub fn connect(&self, addr: SocketAddr) -> Result<()> {
        net::connect(&self.socket, &addr.to_rustix())?;
        Ok(())
    }

    /// Open a connection to a remote host with specified cid and port (you need to bind to an
    /// address with [`Self::bind`] first).
    ///
    /// Allows you to send and receive messages from this host directly through [`Self::send`] and
    /// [`Self::recv`].
    pub fn connect_with_cid_port(&self, cid: u32, port: u32) -> Result<()> {
        self.connect(SocketAddr::new(cid, port))
    }

    /// Send data to the connected remote host.
    ///
    /// Analogous to [`std::net::UdpSocket::send`]
    pub fn send(&self, buf: &[u8]) -> Result<usize> {
        Ok(net::send(&self.socket, buf, default_send_msg_flags())?)
    }

    /// Receive data from the connected remote host.
    ///
    /// Analogous to [`std::net::UdpSocket::recv`]
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let (recv, _) = net::recv(&self.socket, buf, net::RecvFlags::empty())?;
        Ok(recv)
    }

    /// Move this stream in and out of nonblocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        io::ioctl_fionbio(&self.socket, nonblocking)?;
        Ok(())
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

#[allow(unsafe_code)]
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

/// A virtio stream between a local and a remote socket.
///
/// This is the vsock equivalent of [`std::net::TcpStream`].
#[derive(Debug)]
pub struct VsockStream {
    socket: OwnedFd,
}

impl VsockStream {
    /// Open a connection to a remote host.
    pub fn connect(addr: SocketAddr) -> Result<Self> {
        let socket = new_socket(net::SocketType::STREAM)?;
        net::connect(&socket, &addr.to_rustix())?;
        Ok(Self { socket })
    }

    /// Open a connection to a remote host with specified cid and port.
    pub fn connect_with_cid_port(cid: u32, port: u32) -> Result<Self> {
        Self::connect(SocketAddr::new(cid, port))
    }

    /// Virtio socket address of the remote peer associated with this connection.
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        cvt_addr(net::getpeername(&self.socket)?)
    }

    /// Virtio socket address of the local address associated with this connection.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(SocketAddr::from_rustix(
            net::getsockname(&self.socket)?.try_into()?,
        ))
    }

    /// Shutdown the read, write, or both halves of this connection.
    pub fn shutdown(&self, how: Shutdown) -> Result<()> {
        let how = match how {
            Shutdown::Write => net::Shutdown::Write,
            Shutdown::Read => net::Shutdown::Read,
            Shutdown::Both => net::Shutdown::Both,
        };
        Ok(net::shutdown(&self.socket, how)?)
    }

    /// Create a new independently owned handle to the underlying socket.
    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            socket: self.socket.try_clone()?,
        })
    }

    /// Set the timeout on read operations.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> Result<()> {
        net::sockopt::set_socket_timeout(&self.socket, net::sockopt::Timeout::Recv, dur)?;
        Ok(())
    }

    /// Set the timeout on write operations.
    pub fn set_write_timeout(&self, dur: Option<Duration>) -> Result<()> {
        net::sockopt::set_socket_timeout(&self.socket, net::sockopt::Timeout::Send, dur)?;
        Ok(())
    }

    /// Retrieve the latest error associated with the underlying socket.
    pub fn take_error(&self) -> Result<Option<Error>> {
        let error = net::sockopt::socket_error(&self.socket)?;
        match error {
            Ok(()) => Ok(None),
            Err(err) => Ok(Some(err.into())),
        }
    }

    /// Move this stream in and out of nonblocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        io::ioctl_fionbio(&self.socket, nonblocking)?;
        Ok(())
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
        let (recv, _) = net::recv(&self.socket, buf, net::RecvFlags::empty())?;
        Ok(recv)
    }
}

impl Write for &VsockStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        Ok(net::send(&self.socket, buf, default_send_msg_flags())?)
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

#[allow(unsafe_code)]
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

/// Gets the CID of the local machine.
///
/// Note that when calling [`VsockListener::bind`], you should generally use [`VMADDR_CID_ANY`]
/// instead, and for making a loopback connection you should use [`VMADDR_CID_LOCAL`].
#[allow(unsafe_code)]
pub fn get_local_cid() -> Result<u32> {
    use rustix::ioctl;

    const IOCTL_VM_SOCKETS_GET_LOCAL_CID: ioctl::Opcode = 0x7b9;

    let f = File::open("/dev/vsock")?;

    // SAFETY: the kernel only modifies the given u32 integer.
    let cid = unsafe {
        ioctl::ioctl(
            &f,
            ioctl::Getter::<IOCTL_VM_SOCKETS_GET_LOCAL_CID, u32>::new(),
        )
    }?;

    Ok(cid)
}
