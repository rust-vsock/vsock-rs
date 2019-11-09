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

use clap::{crate_authors, crate_version, App, AppSettings, Arg, SubCommand};
use nix::sys::socket::{SockAddr, VsockAddr};
use std::io::Read;
use std::io::Write;
use std::net::Shutdown;
use std::thread;
use vsock::VsockListener;

const BLOCK_SIZE: usize = 16384;

/// Synchronous blocking vsock echo server implementation.
fn sync_server(listen_port: u32) {
    let listener = VsockListener::bind(&SockAddr::Vsock(VsockAddr::new(
        libc::VMADDR_CID_ANY,
        listen_port,
    )))
    .expect("bind and listen failed");
    println!("Server listening for connections on port {}", listen_port);
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                println!(
                    "New connection: {}",
                    stream.peer_addr().expect("unable to get peer address")
                );
                thread::spawn(move || {
                    let mut buf = vec![];
                    buf.resize(BLOCK_SIZE, 0);
                    loop {
                        let read_bytes = match stream.read(&mut buf) {
                            Ok(0) => break,
                            Ok(read_bytes) => read_bytes,
                            Err(e) => panic!("read failed {}", e),
                        };

                        let mut total_written = 0;
                        while total_written < read_bytes {
                            let written_bytes = match stream.write(&buf[total_written..read_bytes])
                            {
                                Ok(0) => break,
                                Ok(written_bytes) => written_bytes,
                                Err(e) => panic!("write failed {}", e),
                            };
                            total_written += written_bytes;
                        }
                    }

                    stream.shutdown(Shutdown::Both).expect("shutdown failed");
                });
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

/// A simple vsock echo server.
/// Bind and listen for incoming connections, and for each connection, read any received data
/// and echo the reply back. Implements two different vsock implementations, synchronous
/// blocking, and event driven.
fn main() {
    let matches = App::new("echo_server")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Virtio sockets test server")
        .setting(AppSettings::ArgRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("sync")
                .version(crate_version!())
                .author(crate_authors!())
                .about("Synchronous echo server implementation")
                .arg(
                    Arg::with_name("listen")
                        .long("listen")
                        .short("l")
                        .help("Port to listen for socket connections")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        ("sync", Some(args)) => {
            let listen_port = args
                .value_of("listen")
                .map(|port| port.parse::<u32>().expect("unable to parse port"))
                .expect("port missing");
            sync_server(listen_port);
        }
        _ => panic!("no valid subcommand provided"),
    }
}
