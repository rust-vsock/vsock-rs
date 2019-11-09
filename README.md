# vsock-rs

Virtio socket support for Rust. Implements VsockListener and VsockStream
which are analogous to the std::net::TcpListener and std::net::TcpStream types. 

## Usage

Refer to the crate documentation.

## Testing

### Prerequisites

You will need qemu-system-x86_64, which can be installed on Debian with:

```
apt-get install qemu-system-x86
```

### Host

Setup the required virtio kernel modules:

```
make kmod
```

Start the test vm, you can shutdown the vm with the keyboard shortcut ```Ctrl+A``` and then ```x```:

```
make vm
```

### Tests

Run the test suite with:

```
make check
```

## Roadmap

* Develop futures/tokio/mio compatible async implementation.