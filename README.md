# RedoxFS

This is the default filesystem of Redox OS inspired by [ZFS](https://docs.freebsd.org/en/books/handbook/zfs/) and adapted to a microkernel architecture.

(It's a replacement for [TFS](https://gitlab.redox-os.org/redox-os/tfs))

Current features:

- Compatible with Redox and Linux (FUSE)
- Copy-on-write
- Data/metadata checksums
- Transparent encryption
- Standard Unix file attributes
- File/directory size limit up to 193TiB (212TB)
- File/directory quantity limit up to 4 billion per 193TiB (2^32 - 1 = 4294967295)
- MIT licensed
- Disk encryption fully supported by the Redox bootloader, letting it load the kernel off an encrypted partition.

Being MIT licensed, RedoxFS can be bundled on GPL-licensed operating systems (Linux, for example).

### How to mount a partition

- Install RedoxFS

```sh
cargo install redoxfs
```

You can also build RedoxFS from this repository.

- Configure your storage device to allow rootless usage

If you are on Linux you need root permission to acess block devices (storage), but it's recommended to run RedoxFS as rootless.

To do that you need to configure your storage device permission to your user with the following command:

```sh
sudo setfacl -m u:your-username:rw /path/to/disk
```

- Mount your RedoxFS partition

```sh
redoxfs /path/to/disk /path/to/mount
```

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![crates.io](http://meritbadge.herokuapp.com/redoxfs)](https://crates.io/crates/redoxfs)
[![docs.rs](https://docs.rs/redoxfs/badge.svg)](https://docs.rs/redoxfs)
