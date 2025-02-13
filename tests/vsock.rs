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
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use vsock::{get_local_cid, VsockAddr, VsockListener, VsockStream, VMADDR_CID_HOST};

const TEST_BLOB_SIZE: usize = 1_000_000;
const TEST_BLOCK_SIZE: usize = 5_000;

const SERVER_CID: u32 = 3;
const SERVER_PORT: u32 = 8000;
const LISTEN_PORT: u32 = 9000;

/// A simple test for the vsock implementation.
/// Generate a large random blob of binary data, and transfer it in chunks over the VsockStream
/// interface. The vm enpoint is running a simple echo server, so for each chunk we will read
/// it's reply and compute a checksum. Comparing the data sent and received confirms that the
/// vsock implementation does not introduce corruption and properly implements the interface
/// semantics.
#[test]
fn test_vsock() {
    let mut rng = rand::rng();
    let mut blob: Vec<u8> = vec![];
    let mut rx_blob = vec![];
    let mut tx_pos = 0;

    blob.resize(TEST_BLOB_SIZE, 0);
    rx_blob.resize(TEST_BLOB_SIZE, 0);
    rng.fill_bytes(&mut blob);

    let mut stream =
        VsockStream::connect(&VsockAddr::new(SERVER_CID, SERVER_PORT)).expect("connection failed");

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
fn test_get_local_cid() {
    assert_eq!(get_local_cid().unwrap(), VMADDR_CID_HOST);
}

#[test]
fn test_listener_local_addr() {
    let listener = VsockListener::bind(&VsockAddr::new(VMADDR_CID_HOST, LISTEN_PORT)).unwrap();

    let local_addr = listener.local_addr().unwrap();
    assert_eq!(local_addr.cid(), VMADDR_CID_HOST);
    assert_eq!(local_addr.port(), LISTEN_PORT);
}

#[test]
fn test_stream_addresses() {
    let stream =
        VsockStream::connect(&VsockAddr::new(SERVER_CID, SERVER_PORT)).expect("connection failed");

    let local_addr = stream.local_addr().unwrap();
    // Apparently on some systems a client socket has the host CID, on some it has CID_ANY. Allow
    // either.
    assert!([libc::VMADDR_CID_ANY, VMADDR_CID_HOST].contains(&local_addr.cid()));

    let peer_addr = stream.peer_addr().unwrap();
    assert_eq!(peer_addr.cid(), SERVER_CID);
    assert_eq!(peer_addr.port(), SERVER_PORT);
}
