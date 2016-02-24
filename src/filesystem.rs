use alloc::boxed::Box;

use collections::{BTreeMap, String};

use core::cmp;

use core::fmt::Display;

use super::{Disk, Header, Node};

/// A file system
pub struct FileSystem<E> {
    pub disk: Box<Disk<E>>,
    pub header: Header,
    pub nodes: BTreeMap<u64, Node>,
}

impl<E: Display> FileSystem<E> {
    /// Create a file system from a disk
    pub fn new(mut disk: Box<Disk<E>>) -> Result<Self, String> {
        let mut header = Header::new();
        try!(disk.read_at(1, &mut header).map_err(|err| format!("{}: could not read header: {}", disk.name(), err)));
        if header.valid() {
            let mut nodes = BTreeMap::new();
            for extent in &header.extents {
                if extent.block > 0 && extent.length > 0 {
                    let current_sectors = (extent.length + 511) / 512;
                    let max_size = current_sectors * 512;

                    let size = cmp::min(extent.length, max_size);

                    for i in 0..size / 512 {
                        let node_block = extent.block + i;
                        let mut node = Node::new();
                        try!(disk.read_at(node_block, &mut node).map_err(|err| format!("{}: could not read node {}: {}", disk.name(), node_block, err)));
                        nodes.insert(node_block, node);
                    }
                }
            }

            Ok(FileSystem {
                disk: disk,
                header: header,
                nodes: nodes,
            })
        }else{
            Err(format!("{}: invalid header", disk.name()))
        }
    }
}
