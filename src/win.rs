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

use std::convert::TryInto;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::mem::{size_of, transmute};
use std::net::Shutdown;
use std::ptr;
use std::sync::Once;
use std::time::Duration;

use widestring::U16String;
use windows::core::{GUID, PCSTR, PSTR, PWSTR};
use windows::Win32::Networking::WinSock::*;
use windows::Win32::System::Diagnostics::Debug;
use windows::Win32::System::Hypervisor::{
    HV_GUID_VSOCK_TEMPLATE, HV_GUID_ZERO, HV_PROTOCOL_RAW, SOCKADDR_HV,
};
use windows::Win32::System::Memory::LocalFree;

static INIT: Once = Once::new();

fn wsa_init() {
    INIT.call_once(|| {
        // Initialize WSA for use
        drop(std::net::UdpSocket::bind("127.0.0.1:0"));
    });
}

fn new_socket() -> SOCKET {
    unsafe { socket(AF_HYPERV as i32, SOCK_STREAM as i32, HV_PROTOCOL_RAW as i32) }
}

pub fn svcid_from_port(port: u32) -> GUID {
    let mut ret = HV_GUID_VSOCK_TEMPLATE;
    ret.data1 = port;
    ret
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

unsafe fn get_wsa_error(err: WSA_ERROR) -> Error {
    let mut buf = PWSTR::default();
    let buf_ref: PWSTR = PWSTR(transmute::<&mut PWSTR, *mut u16>(&mut buf));
    let len = Debug::FormatMessageW(
        Debug::FORMAT_MESSAGE_FROM_SYSTEM
            | Debug::FORMAT_MESSAGE_ALLOCATE_BUFFER
            | Debug::FORMAT_MESSAGE_IGNORE_INSERTS,
        ptr::null(),
        err.0 as u32,
        0,
        buf_ref,
        0,
        ptr::null_mut(),
    );
    if len == 0 {
        return Error::new(ErrorKind::Other, format!("WSA Error {}", err.0 as u32));
    }
    let err_s = U16String::from_ptr(buf.0, len as usize);

    LocalFree(buf.0 as isize);

    Error::new(
        ErrorKind::Other,
        format!("WSA Error {}: {}", err.0 as u32, err_s.to_string_lossy()),
    )
}

fn get_last_wsa_error() -> Error {
    unsafe { get_wsa_error(WSAGetLastError()) }
}

/// A virtio socket server, listening for connections.
#[derive(Debug, Clone)]
pub struct VsockListener {
    socket: SOCKET,
}

impl VsockListener {
    /// Create a new VsockListener which is bound and listening on the socket address.
    pub fn bind(addr: &SOCKADDR_HV) -> Result<VsockListener> {
        wsa_init();
        if addr.Family != AF_HYPERV {
            return Err(Error::new(
                ErrorKind::Other,
                "requires a hyper-v socket address",
            ));
        };

        let socket = new_socket();
        if socket == INVALID_SOCKET {
            return Err(get_last_wsa_error());
        }

        let res = unsafe {
            bind(
                socket,
                transmute::<&SOCKADDR_HV, &SOCKADDR>(&addr),
                size_of::<SOCKADDR_HV>() as i32,
            )
        };
        if res == SOCKET_ERROR {
            return Err(get_last_wsa_error());
        }

        // rust stdlib uses a 128 connection backlog
        let res = unsafe { listen(socket, 128) };
        if res == SOCKET_ERROR {
            return Err(get_last_wsa_error());
        }

        Ok(Self { socket })
    }

    /// Create a new VsockListener with specified VM and Service IDs
    pub fn bind_with_vmid_svcid(vmid: GUID, svcid: GUID) -> Result<VsockListener> {
        let addr = SOCKADDR_HV {
            Family: AF_HYPERV,
            Reserved: 0,
            VmId: vmid,
            ServiceId: svcid,
        };
        Self::bind(&addr)
    }

    /// The local socket address of the listener.
    pub fn local_addr(&self) -> Result<SOCKADDR> {
        let mut hv_addr = SOCKADDR::default();
        let mut hv_addr_len = size_of::<SOCKADDR>() as i32;
        if unsafe { getsockname(self.socket, &mut hv_addr, &mut hv_addr_len) } == SOCKET_ERROR {
            Err(get_last_wsa_error())
        } else {
            Ok(hv_addr)
        }
    }

    /// Create a new independently owned handle to the underlying socket.
    pub fn try_clone(&self) -> Result<Self> {
        Ok(self.clone())
    }

    /// Accept a new incoming connection from this listener.
    pub fn accept(&self) -> Result<(VsockStream, SOCKADDR_HV)> {
        let mut vsock_addr = SOCKADDR_HV {
            Family: AF_HYPERV,
            Reserved: 0,
            VmId: HV_GUID_ZERO,
            ServiceId: HV_GUID_ZERO,
        };
        let mut vsock_addr_len = size_of::<SOCKADDR_HV>() as i32;
        let vsock = unsafe {
            accept(
                self.socket,
                transmute::<&mut SOCKADDR_HV, &mut SOCKADDR>(&mut vsock_addr),
                &mut vsock_addr_len,
            )
        };
        if vsock == INVALID_SOCKET {
            Err(get_last_wsa_error())
        } else {
            Ok((VsockStream { socket: vsock }, vsock_addr))
        }
    }

    /// An iterator over the connections being received on this listener.
    pub fn incoming(&self) -> Incoming {
        Incoming { listener: self }
    }

    /// Retrieve the latest error associated with the underlying socket.
    pub fn take_error(&self) -> Result<Option<Error>> {
        let mut error: i32 = 0;
        let mut error_len: i32 = size_of::<i32>() as i32;
        if unsafe {
            getsockopt(
                self.socket,
                transmute::<u32, i32>(SOL_SOCKET),
                transmute::<u32, i32>(SO_ERROR),
                PSTR(&mut error as *mut i32 as *mut u8),
                &mut error_len,
            )
        } == SOCKET_ERROR
        {
            Err(get_last_wsa_error())
        } else {
            Ok(if error == 0 {
                None
            } else {
                Some(unsafe { get_wsa_error(WSA_ERROR(error)) })
            })
        }
    }

    /// Move this stream in and out of nonblocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        let mut nonblocking: u32 = if nonblocking { 1 } else { 0 };
        if unsafe { ioctlsocket(self.socket, FIONBIO, &mut nonblocking) } == SOCKET_ERROR {
            Err(get_last_wsa_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for VsockListener {
    fn drop(&mut self) {
        unsafe { closesocket(self.socket) };
    }
}

/// A virtio stream between a local and a remote socket.
#[derive(Debug, Clone)]
pub struct VsockStream {
    socket: SOCKET,
}

impl VsockStream {
    /// Open a connection to a remote host.
    pub fn connect(addr: &SOCKADDR_HV) -> Result<Self> {
        wsa_init();
        if addr.Family != AF_HYPERV {
            return Err(Error::new(
                ErrorKind::Other,
                "requires a hyper-v socket address",
            ));
        };

        let sock = new_socket();
        if sock == INVALID_SOCKET {
            return Err(get_last_wsa_error());
        }
        if unsafe {
            connect(
                sock,
                transmute::<&SOCKADDR_HV, &SOCKADDR>(&addr),
                size_of::<SOCKADDR_HV>() as i32,
            )
        } == SOCKET_ERROR
        {
            Err(get_last_wsa_error())
        } else {
            Ok(VsockStream { socket: sock })
        }
    }

    /// Open a connection to a remote host with specified VM and Service IDs
    pub fn connect_with_vmid_svcid(vmid: GUID, svcid: GUID) -> Result<VsockStream> {
        let addr = SOCKADDR_HV {
            Family: AF_HYPERV,
            Reserved: 0,
            VmId: vmid,
            ServiceId: svcid,
        };
        Self::connect(&addr)
    }

    /// Virtio socket address of the remote peer associated with this connection.
    pub fn peer_addr(&self) -> Result<SOCKADDR_HV> {
        let mut vsock_addr = SOCKADDR_HV {
            Family: AF_HYPERV,
            Reserved: 0,
            VmId: HV_GUID_ZERO,
            ServiceId: HV_GUID_ZERO,
        };
        let mut vsock_addr_len = size_of::<SOCKADDR_HV>() as i32;
        if unsafe {
            getpeername(
                self.socket,
                transmute::<&mut SOCKADDR_HV, &mut SOCKADDR>(&mut vsock_addr),
                &mut vsock_addr_len,
            )
        } == SOCKET_ERROR
        {
            Err(get_last_wsa_error())
        } else {
            Ok(vsock_addr)
        }
    }

    /// Virtio socket address of the local address associated with this connection.
    pub fn local_addr(&self) -> Result<SOCKADDR_HV> {
        let mut vsock_addr = SOCKADDR_HV {
            Family: AF_HYPERV,
            Reserved: 0,
            VmId: HV_GUID_ZERO,
            ServiceId: HV_GUID_ZERO,
        };
        let mut vsock_addr_len = size_of::<SOCKADDR_HV>() as i32;
        if unsafe {
            getsockname(
                self.socket,
                transmute::<&mut SOCKADDR_HV, &mut SOCKADDR>(&mut vsock_addr),
                &mut vsock_addr_len,
            )
        } == SOCKET_ERROR
        {
            Err(get_last_wsa_error())
        } else {
            Ok(vsock_addr)
        }
    }

    /// Shutdown the read, write, or both halves of this connection.
    pub fn shutdown(&self, how: Shutdown) -> Result<()> {
        let how = match how {
            Shutdown::Write => SD_SEND,
            Shutdown::Read => SD_RECEIVE,
            Shutdown::Both => SD_BOTH,
        };
        if unsafe { shutdown(self.socket, how as i32) } == SOCKET_ERROR {
            Err(get_last_wsa_error())
        } else {
            Ok(())
        }
    }

    /// Create a new independently owned handle to the underlying socket.
    pub fn try_clone(&self) -> Result<Self> {
        Ok(self.clone())
    }

    /// Set the timeout on read operations.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> Result<()> {
        let timeout = Self::ms_from_duration(dur)?;
        if unsafe {
            setsockopt(
                self.socket,
                SOL_SOCKET as i32,
                SO_SNDTIMEO as i32,
                PCSTR(&timeout as *const u32 as *const u8),
                size_of::<u32>() as i32,
            )
        } == SOCKET_ERROR
        {
            Err(get_last_wsa_error())
        } else {
            Ok(())
        }
    }

    /// Set the timeout on write operations.
    pub fn set_write_timeout(&self, dur: Option<Duration>) -> Result<()> {
        let timeout = Self::ms_from_duration(dur)?;
        if unsafe {
            setsockopt(
                self.socket,
                SOL_SOCKET as i32,
                SO_RCVTIMEO as i32,
                PCSTR(&timeout as *const u32 as *const u8),
                size_of::<u32>() as i32,
            )
        } == SOCKET_ERROR
        {
            Err(get_last_wsa_error())
        } else {
            Ok(())
        }
    }

    /// Retrieve the latest error associated with the underlying socket.
    pub fn take_error(&self) -> Result<Option<Error>> {
        let mut error: i32 = 0;
        let mut error_len: i32 = size_of::<i32>() as i32;
        if unsafe {
            getsockopt(
                self.socket,
                SOL_SOCKET as i32,
                SO_ERROR as i32,
                PSTR(&mut error as *mut i32 as *mut u8),
                &mut error_len,
            )
        } == SOCKET_ERROR
        {
            Err(get_last_wsa_error())
        } else {
            Ok(if error == 0 {
                None
            } else {
                Some(unsafe { get_wsa_error(WSA_ERROR(error)) })
            })
        }
    }

    /// Move this stream in and out of nonblocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        let mut nonblocking: u32 = if nonblocking { 1 } else { 0 };
        if unsafe { ioctlsocket(self.socket, FIONBIO, &mut nonblocking) } == SOCKET_ERROR {
            Err(get_last_wsa_error())
        } else {
            Ok(())
        }
    }

    fn ms_from_duration(dur: Option<Duration>) -> Result<u32> {
        match dur {
            Some(dur) => {
                if dur.is_zero() {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "cannot set a zero duration timeout",
                    ));
                }
                if dur.as_millis() > u32::MAX as u128 {
                    Ok(u32::MAX)
                } else {
                    Ok(dur.as_millis().try_into().unwrap())
                }
            }
            None => Ok(0),
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
        let ret = unsafe {
            recv(
                self.socket,
                PSTR(buf.as_mut_ptr()),
                buf.len().try_into().unwrap_or(i32::MAX),
                0,
            )
        };
        if ret == SOCKET_ERROR {
            Err(get_last_wsa_error())
        } else {
            Ok(ret as usize)
        }
    }
}

impl Write for &VsockStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let ret = unsafe {
            send(
                self.socket,
                PCSTR(buf.as_ptr()),
                buf.len().try_into().unwrap_or(i32::MAX),
                SEND_FLAGS(0),
            )
        };
        if ret == SOCKET_ERROR {
            Err(get_last_wsa_error())
        } else {
            Ok(ret as usize)
        }
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Drop for VsockStream {
    fn drop(&mut self) {
        unsafe { closesocket(self.socket) };
    }
}
