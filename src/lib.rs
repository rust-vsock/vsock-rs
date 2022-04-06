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

// UNIX exports
#[cfg(target_os = "unix")]
mod unix;
#[cfg(target_os = "unix")]
pub use libc::{VMADDR_CID_ANY, VMADDR_CID_HOST, VMADDR_CID_HYPERVISOR, VMADDR_CID_LOCAL};
#[cfg(target_os = "unix")]
pub use nix::sys::socket::{SockAddr, VsockAddr};
#[cfg(target_os = "unix")]
pub use unix::{get_local_cid, Incoming, VsockListener, VsockStream};

// Windows exports
#[cfg(target_os = "windows")]
mod win;
#[cfg(target_os = "windows")]
pub use win::{svcid_from_port, Incoming, VsockListener, VsockStream};
#[cfg(target_os = "windows")]
pub use windows::core::GUID;
#[cfg(target_os = "windows")]
pub use windows::Win32::Networking::WinSock::{AF_HYPERV, SOCKADDR, SOCKET};
#[cfg(target_os = "windows")]
pub use windows::Win32::System::Hypervisor::{
    HV_GUID_BROADCAST, HV_GUID_CHILDREN, HV_GUID_LOOPBACK, HV_GUID_PARENT, HV_GUID_VSOCK_TEMPLATE,
    HV_GUID_ZERO, SOCKADDR_HV,
};
