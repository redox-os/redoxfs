use alloc::boxed::Box;

use super::{Disk, Header, Node};

/// A file system
pub struct FileSystem<E> {
    pub disk: Box<Disk<E>>,
    pub header: Header,
}

impl<E> FileSystem<E> {
    /// Open a file system on a disk
    pub fn open(mut disk: Box<Disk<E>>) -> Result<Option<Self>, E> {
        let mut header = Header::default();
        try!(disk.read_at(1, &mut header));
        if header.valid() {
            Ok(Some(FileSystem {
                disk: disk,
                header: header,
            }))
        }else{
            Ok(None)
        }
    }

    /// Create a file system on a disk
    pub fn create(mut disk: Box<Disk<E>>) -> Result<Self, E> {
        let header = Header::new();
        try!(disk.write_at(1, &header));
        Ok(FileSystem {
            disk: disk,
            header: header,
        })
    }

    pub fn node(&mut self, block: u64) -> Result<Node, E> {
        let mut node = Node::default();
        try!(self.disk.read_at(block, &mut node));
        Ok(node)
    }
}
