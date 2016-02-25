use alloc::boxed::Box;

use collections::vec::Vec;

use super::{Disk, ExNode, Extent, Header, Node};

/// A file system
pub struct FileSystem<E> {
    pub disk: Box<Disk<E>>,
    pub header: (u64, Header),
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
            let mut free = (3, Node::new(Node::MODE_FILE, "free", 0));
            free.1.extents[0] = Extent::new(4, (size - 4 * 512));
            try!(disk.write_at(free.0, &free.1));

            let root = (2, Node::new(Node::MODE_DIR, "root", 0));
            try!(disk.write_at(root.0, &root.1));

            let header = (1, Header::new(size, root.0, free.0));
            try!(disk.write_at(header.0, &header.1));

            Ok(Some(FileSystem {
                disk: disk,
                header: header,
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

    pub fn deallocate(&mut self, _block: u64) -> Result<bool, E> {
        Ok(false)
    }

    pub fn node(&mut self, block: u64) -> Result<(u64, Node), E> {
        let mut node = Node::default();
        try!(self.disk.read_at(block, &mut node));
        Ok((block, node))
    }

    pub fn ex_node(&mut self, block: u64) -> Result<(u64, ExNode), E> {
        let mut node = ExNode::default();
        try!(self.disk.read_at(block, &mut node));
        Ok((block, node))
    }

    pub fn child_nodes(&mut self, children: &mut Vec<(u64, Node)>, parent_block: u64) -> Result<(), E> {
        if parent_block == 0 {
            return Ok(());
        }

        let parent = try!(self.node(parent_block));
        for extent in parent.1.extents.iter() {
            for i in 0 .. extent.length/512 {
                children.push(try!(self.node(extent.block + i)));
            }
        }

        self.child_nodes(children, parent.1.next)
    }

    pub fn find_node(&mut self, name: &str, parent_block: u64) -> Result<Option<(u64, Node)>, E> {
        if parent_block == 0 {
            return Ok(None);
        }

        let parent = try!(self.node(parent_block));
        for extent in parent.1.extents.iter() {
            for i in 0 .. extent.length/512 {
                let child = try!(self.node(extent.block + i));

                let mut matches = false;
                if let Ok(child_name) = child.1.name() {
                    if child_name == name {
                        matches = true;
                    }
                }

                if matches {
                    return Ok(Some(child));
                }
            }
        }

        self.find_node(name, parent.1.next)
    }

    fn insert_block(&mut self, block: u64, parent_block: u64) -> Result<bool, E> {
        if parent_block == 0 {
            return Ok(false);
        }

        let mut inserted = false;
        let mut parent = try!(self.node(parent_block));
        for mut extent in parent.1.extents.iter_mut() {
            if extent.length == 0 {
                //New extent
                inserted = true;
                extent.block = block;
                extent.length = 512;
                break;
            } else if extent.block == block + 1 {
                //At beginning
                inserted = true;
                extent.block = block;
                extent.length += 512;
            } else if extent.block + extent.length/512 == block {
                //At end
                inserted = true;
                extent.length += 512;
                break;
            }
        }

        if inserted {
            try!(self.disk.write_at(parent.0, &parent.1));
            Ok(true)
        } else {
            if parent.1.next == 0 {
                if let Some(block) = try!(self.allocate()) {
                    parent.1.next = block;
                    try!(self.disk.write_at(parent.0, &parent.1));
                    try!(self.disk.write_at(parent.1.next, &Node::default()));
                } else {
                    return Ok(false);
                }
            }

            self.insert_block(block, parent.1.next)
        }
    }

    pub fn create_node(&mut self, mode: u16, name: &str, parent_block: u64) -> Result<Option<(u64, Node)>, E> {
        if let Some(block) = try!(self.allocate()) {
            let node = (block, Node::new(mode, name, parent_block));
            try!(self.disk.write_at(node.0, &node.1));

            if try!(self.insert_block(block, parent_block)) {
                Ok(Some(node))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    pub fn remove_node(&mut self, _name: &str) -> Result<bool, E> {
        Ok(false)
    }
}
