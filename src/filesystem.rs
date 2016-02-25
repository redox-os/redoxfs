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
    pub fn create(mut disk: Box<Disk<E>>) -> Result<Option<Self>, E> {
        let size = try!(disk.size());

        if size >= 4 * 512 {
            let mut free = (3, Node::new("free", Node::MODE_FILE));
            free.1.extents[0] = Extent::new(4, (size - 4 * 512));
            try!(disk.write_at(free.0, &free.1));

            let root = (2, Node::new("root", Node::MODE_DIR));
            try!(disk.write_at(root.0, &root.1));

            let header = (1, Header::new(size, root.0, free.0));
            try!(disk.write_at(header.0, &header.1));

            Ok(Some(FileSystem {
                disk: disk,
                header: header,
                root: root,
                free: free
            }))
        } else {
            Ok(None)
        }
    }

    pub fn allocate(&mut self) -> Result<Option<u64>, E> {
        let mut block = None;
        for mut extent in self.free.1.extents.iter_mut() {
            if extent.length >= 512 {
                block = Some(extent.block);
                extent.length -= 512;
                extent.block += 1;
                break;
            }
        }
        if block.is_some() {
            try!(self.disk.write_at(self.free.0, &self.free.1));
        }
        Ok(block)
    }

    pub fn node(&mut self, block: u64) -> Result<Node, E> {
        let mut node = Node::default();
        try!(self.disk.read_at(block, &mut node));
        Ok(node)
    }

    fn create_node(&mut self, name: &str, mode: u64) -> Result<Option<(u64, Node)>, E> {
        if let Some(block) = try!(self.allocate()) {
            let node = (block, Node::new(name, mode));
            try!(self.disk.write_at(node.0, &node.1));

            let mut inserted = false;
            let mut last_node = (0, Node::default());
            let mut next_node = (self.header.1.root, Node::default());
            while ! inserted {
                if next_node.0 > 0 {
                    try!(self.disk.read_at(next_node.0, &mut next_node.1));
                }else{
                    if let Some(block) = try!(self.allocate()) {
                        next_node.0 = block;
                        if last_node.0 > 0 {
                            last_node.1.next = block;
                            if last_node.0 == self.root.0 {
                                self.root.1.next = last_node.1.next;
                            }
                            try!(self.disk.write_at(last_node.0, &last_node.1));
                        } else {
                            panic!("last_node was 0");
                        }
                    } else {
                        return Ok(None);
                    }
                }

                for mut extent in next_node.1.extents.iter_mut() {
                    if extent.length == 0 {
                        inserted = true;
                        extent.length = 512;
                        extent.block = block;
                        break;
                    }
                }

                if inserted {
                    if next_node.0 == self.root.0 {
                        self.root.1.extents = next_node.1.extents;
                    }
                    try!(self.disk.write_at(next_node.0, &next_node.1));
                } else {
                    last_node = next_node;
                    next_node = (last_node.1.next, Node::default());
                }
            }

            Ok(Some(node))
        } else {
            Ok(None)
        }
    }

    pub fn create_dir(&mut self, name: &str) -> Result<Option<(u64, Node)>, E> {
        self.create_node(name, Node::MODE_DIR)
    }

    pub fn create_file(&mut self, name: &str) -> Result<Option<(u64, Node)>, E> {
        self.create_node(name, Node::MODE_FILE)
    }
}
