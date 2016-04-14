# RedoxFS Design Document

## Structures

### Header
The header is the entry point for the filesystem. When mounting a disk or image, it should be scanned for a block starting with the 8-byte signature, within the first megabyte:
```rust
"RedoxFS\0"
```

The header stores the filesystem version, disk identifier, disk size, root block pointer, and free block pointer.

```rust
#[repr(packed)]
pub struct Header {
    pub signature: [u8; 8],
    pub version: u64,
    pub uuid: [u8; 16],
    pub size: u64,
    pub root: u64,
    pub free: u64,
}
```

The root and free block pointers point to a Node that identifies

### Node

```rust
#[repr(packed)]
pub struct Node {
    pub name: [u8; 256],
    pub mode: u64,
    pub next: u64,
    pub extents: [Extent; 15],
}
```
