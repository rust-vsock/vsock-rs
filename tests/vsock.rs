/*
 * Copyright 2019 fsyncd, Berlin, Germany.
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

use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::ptr;

#[cfg(target_os = "unix")]
use vsock::{get_local_cid, SockAddr, VsockAddr, VsockStream, VMADDR_CID_HOST};

#[cfg(target_os = "windows")]
use vsock::{svcid_from_port, VsockStream};
#[cfg(target_os = "windows")]
use widestring::U16CString;
#[cfg(target_os = "windows")]
use windows::core::GUID;
#[cfg(target_os = "windows")]
use windows::core::PCWSTR;
#[cfg(target_os = "windows")]
use windows::Win32::System::HostComputeSystem::{
    HcsCreateOperation, HcsEnumerateComputeSystems, HcsWaitForOperationResult,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Memory::LocalFree;
#[cfg(target_os = "windows")]
use uuid::Uuid;

#[cfg(target_os = "windows")]
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ComputeSystem {
    pub id: Uuid,
    pub system_type: String,
    pub owner: String,
    pub runtime_id: Uuid,
    pub state: String,
}

#[cfg(target_os = "windows")]
unsafe fn get_first_vm() -> GUID {
    let op = HcsCreateOperation(ptr::null(), None);
    if op.is_invalid() {
        panic!("Failed to create operation!");
    }
    HcsEnumerateComputeSystems(PCWSTR(ptr::null()), op).expect("Failed to enumerate systems");
    let result =
        HcsWaitForOperationResult(op, u32::MAX).expect("Failed to wait for operation to complete!");
    let json_str = U16CString::from_ptr_str(result.0).to_string_lossy();
    LocalFree(result.0 as isize);
    let systems: Vec<ComputeSystem> =
        serde_json::from_str(&json_str).expect("Failed to decode HCS JSON");
    let machine = systems.first().expect("No machines found");
    GUID::from_u128(machine.id.as_u128())
}

const TEST_BLOB_SIZE: usize = 1_000_000;
const TEST_BLOCK_SIZE: usize = 5_000;

/// A simple test for the vsock implementation.
/// Generate a large random blob of binary data, and transfer it in chunks over the VsockStream
/// interface. The vm enpoint is running a simple echo server, so for each chunk we will read
/// it's reply and compute a checksum. Comparing the data sent and received confirms that the
/// vsock implementation does not introduce corruption and properly implements the interface
/// semantics.
#[test]
fn test_vsock() {
    let mut rng = rand::thread_rng();
    let mut blob: Vec<u8> = vec![];
    let mut rx_blob = vec![];
    let mut tx_pos = 0;

    blob.resize(TEST_BLOB_SIZE, 0);
    rx_blob.resize(TEST_BLOB_SIZE, 0);
    rng.fill_bytes(&mut blob);

    #[cfg(target_os = "unix")]
    let mut stream =
        VsockStream::connect(&SockAddr::Vsock(VsockAddr::new(3, 8000))).expect("connection failed");
    #[cfg(target_os = "windows")]
    let mut stream =
        VsockStream::connect_with_vmid_svcid(unsafe { get_first_vm() }, svcid_from_port(8000))
            .expect("connection failed");

    while tx_pos < TEST_BLOB_SIZE {
        let written_bytes = stream
            .write(&blob[tx_pos..tx_pos + TEST_BLOCK_SIZE])
            .expect("write failed");
        if written_bytes == 0 {
            panic!("stream unexpectedly closed");
        }

        let mut rx_pos = tx_pos;
        while rx_pos < (tx_pos + written_bytes) {
            let read_bytes = stream.read(&mut rx_blob[rx_pos..]).expect("read failed");
            if read_bytes == 0 {
                panic!("stream unexpectedly closed");
            }
            rx_pos += read_bytes;
        }

        tx_pos += written_bytes;
    }

    let expected = Sha256::digest(&blob);
    let actual = Sha256::digest(&rx_blob);

    assert_eq!(expected, actual);
}

#[test]
#[cfg(target_os = "unix")]
fn test_get_local_cid() {
    assert_eq!(get_local_cid().unwrap(), VMADDR_CID_HOST);
}
