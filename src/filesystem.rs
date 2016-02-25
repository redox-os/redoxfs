use alloc::boxed::Box;

use super::{Disk, Extent, Header, Node};

/// A file system
pub struct FileSystem<E> {
    pub disk: Box<Disk<E>>,
    pub header: (u64, Header),
    pub root: (u64, Node),
    pub free: (u64, Node)
}

impl<E> FileSystem<E> {
    /// Open a file system on a disk
    pub fn open(mut disk: Box<Disk<E>>) -> Result<Option<Self>, E> {
        let mut header = (1, Header::default());
        try!(disk.read_at(header.0, &mut header.1));

        if header.1.valid() {
            let mut root = (header.1.root, Node::default());
            try!(disk.read_at(root.0, &mut root.1));

            let mut free = (header.1.free, Node::default());
            try!(disk.read_at(free.0, &mut free.1));

            Ok(Some(FileSystem {
                disk: disk,
                header: header,
                root: root,
                free: free
            }))
        }else{
            Ok(None)
        }
    }

    /// Create a file system on a disk
    pub fn create(mut disk: Box<Disk<E>>) -> Result<Self, E> {
        let size = try!(disk.size());

        assert!(size > 4);

        let mut free = (3, Node::new("free", Node::MODE_DIR));
        free.1.extents[0] = Extent::new(4, (size - 4 * 512));
        try!(disk.write_at(free.0, &free.1));

        let root = (2, Node::new("root", Node::MODE_DIR));
        try!(disk.write_at(root.0, &root.1));

        let header = (1, Header::new(size, root.0, free.0));
        try!(disk.write_at(header.0, &header.1));

        Ok(FileSystem {
            disk: disk,
            header: header,
            root: root,
            free: free
        })
    }

    pub fn node(&mut self, block: u64) -> Result<Node, E> {
        let mut node = Node::default();
        try!(self.disk.read_at(block, &mut node));
        Ok(node)
    }
}
