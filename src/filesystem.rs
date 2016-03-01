use alloc::boxed::Box;

use collections::vec::Vec;

use system::error::{Result, Error, EEXIST, EISDIR, ENOENT, ENOSPC, ENOTDIR, ENOTEMPTY};

use super::{Disk, ExNode, Extent, Header, Node};

/// A file system
pub struct FileSystem {
    pub disk: Box<Disk>,
    pub header: (u64, Header)
}

impl FileSystem {
    /// Open a file system on a disk
    pub fn open(mut disk: Box<Disk>) -> Result<Self> {
        let mut header = (1, Header::default());
        try!(disk.read_at(header.0, &mut header.1));

        if header.1.valid() {
            let mut root = (header.1.root, Node::default());
            try!(disk.read_at(root.0, &mut root.1));

            let mut free = (header.1.free, Node::default());
            try!(disk.read_at(free.0, &mut free.1));

            Ok(FileSystem {
                disk: disk,
                header: header
            })
        }else{
            Err(Error::new(ENOENT))
        }
    }

    /// Create a file system on a disk
    pub fn create(mut disk: Box<Disk>) -> Result<Self> {
        let size = try!(disk.size())/512;

        if size >= 4 {
            let mut free = (3, Node::new(Node::MODE_FILE, "free", 0));
            free.1.extents[0] = Extent::new(4, size - 4);
            try!(disk.write_at(free.0, &free.1));

            let root = (2, Node::new(Node::MODE_DIR, "root", 0));
            try!(disk.write_at(root.0, &root.1));

            let header = (1, Header::new(size, root.0, free.0));
            try!(disk.write_at(header.0, &header.1));

            Ok(FileSystem {
                disk: disk,
                header: header
            })
        } else {
            Err(Error::new(ENOSPC))
        }
    }

    pub fn allocate(&mut self, length: u64) -> Result<u64> {
        //TODO: traverse next pointer
        let free_block = self.header.1.free;
        let mut free = try!(self.node(free_block));
        let mut block_option = None;
        for mut extent in free.1.extents.iter_mut() {
            if extent.length >= length {
                block_option = Some(extent.block);
                extent.length -= length;
                extent.block += length;
                break;
            }
        }
        if let Some(block) = block_option {
            try!(self.disk.write_at(free.0, &free.1));
            Ok(block)
        } else {
            Err(Error::new(ENOSPC))
        }
    }

    pub fn deallocate(&mut self, block: u64, length: u64) -> Result<()> {
        let free_block = self.header.1.free;
        self.insert_blocks(block, length, free_block)
    }

    pub fn node(&mut self, block: u64) -> Result<(u64, Node)> {
        let mut node = Node::default();
        try!(self.disk.read_at(block, &mut node));
        Ok((block, node))
    }

    pub fn ex_node(&mut self, block: u64) -> Result<(u64, ExNode)> {
        let mut node = ExNode::default();
        try!(self.disk.read_at(block, &mut node));
        Ok((block, node))
    }

    pub fn child_nodes(&mut self, children: &mut Vec<(u64, Node)>, parent_block: u64) -> Result<()> {
        if parent_block == 0 {
            return Ok(());
        }

        let parent = try!(self.node(parent_block));
        for extent in parent.1.extents.iter() {
            for i in 0 .. extent.length {
                children.push(try!(self.node(extent.block + i)));
            }
        }

        self.child_nodes(children, parent.1.next)
    }

    pub fn find_node(&mut self, name: &str, parent_block: u64) -> Result<(u64, Node)> {
        if parent_block == 0 {
            return Err(Error::new(ENOENT));
        }

        let parent = try!(self.node(parent_block));
        for extent in parent.1.extents.iter() {
            for i in 0 .. extent.length {
                let child = try!(self.node(extent.block + i));

                let mut matches = false;
                if let Ok(child_name) = child.1.name() {
                    if child_name == name {
                        matches = true;
                    }
                }

                if matches {
                    return Ok(child);
                }
            }
        }

        self.find_node(name, parent.1.next)
    }

    fn insert_blocks(&mut self, block: u64, length: u64, parent_block: u64) -> Result<()> {
        if parent_block == 0 {
            return Err(Error::new(ENOSPC));
        }

        let mut inserted = false;
        let mut parent = try!(self.node(parent_block));
        for mut extent in parent.1.extents.iter_mut() {
            if extent.length == 0 {
                //New extent
                inserted = true;
                extent.block = block;
                extent.length = length;
                break;
            } else if extent.block == block + length {
                //At beginning
                inserted = true;
                extent.block = block;
                extent.length += length;
                break;
            } else if extent.block + extent.length == block {
                //At end
                inserted = true;
                extent.length += length;
                break;
            }
        }

        if inserted {
            try!(self.disk.write_at(parent.0, &parent.1));
            Ok(())
        } else {
            if parent.1.next == 0 {
                parent.1.next = try!(self.allocate(1));
                try!(self.disk.write_at(parent.0, &parent.1));
                try!(self.disk.write_at(parent.1.next, &Node::default()));
            }

            self.insert_blocks(block, length, parent.1.next)
        }
    }

    pub fn create_node(&mut self, mode: u16, name: &str, parent_block: u64) -> Result<(u64, Node)> {
        if self.find_node(name, parent_block).is_ok() {
            Err(Error::new(EEXIST))
        } else {
            let node = (try!(self.allocate(1)), Node::new(mode, name, parent_block));
            try!(self.disk.write_at(node.0, &node.1));

            try!(self.insert_blocks(node.0, 1, parent_block));

            Ok(node)
        }
    }

    fn remove_blocks(&mut self, block: u64, length: u64, parent_block: u64) -> Result<()> {
        if parent_block == 0 {
            return Err(Error::new(ENOENT));
        }

        let mut removed = false;
        let mut replace_option = None;
        let mut parent = try!(self.node(parent_block));
        for mut extent in parent.1.extents.iter_mut() {
            if block >= extent.block && block + length <= extent.block + extent.length {
                //Inside
                removed = true;

                let left = Extent::new(extent.block, block - extent.block);
                let right = Extent::new(block + length, (extent.block + extent.length) - (block + length));

                if left.length > 0 {
                    *extent = left;

                    if right.length > 0 {
                        replace_option = Some(right);
                    }
                } else if right.length > 0 {
                    *extent = right;
                } else {
                    *extent = Extent::default();
                }

                break;
            }
        }

        if removed {
            try!(self.disk.write_at(parent.0, &parent.1));

            if let Some(replace) = replace_option {
                for i in 0..replace.length {
                    let block = replace.block + i;
                    try!(self.insert_blocks(block, 1, parent_block));
                }
            }

            try!(self.deallocate(block, 1));

            Ok(())
        } else {
            self.remove_blocks(block, length, parent.1.next)
        }
    }

    pub fn remove_node(&mut self, mode: u16, name: &str, parent_block: u64) -> Result<()> {
        let node = try!(self.find_node(name, parent_block));
        if node.1.mode & Node::MODE_TYPE == mode {
            if node.1.is_dir() {
                let mut children = Vec::new();
                try!(self.child_nodes(&mut children, node.0));
                if ! children.is_empty() {
                    return Err(Error::new(ENOTEMPTY));
                }
            }

            try!(self.remove_blocks(node.0, 1, parent_block));
            try!(self.disk.write_at(node.0, &Node::default()));

            Ok(())
        } else if node.1.is_dir() {
            Err(Error::new(EISDIR))
        } else {
            Err(Error::new(ENOTDIR))
        }
    }

    fn node_ensure_len(&mut self, block: u64, mut length: u64) -> Result<()> {
        if block == 0 {
            return Err(Error::new(ENOENT));
        }

        let node = try!(self.node(block));
        for extent in node.1.extents.iter() {
            if extent.length >= length {
                length = 0;
                break;
            } else {
                length -= extent.length;
            }
        }

        if length > 0 {
            if node.1.next > 0 {
                self.node_ensure_len(node.1.next, length)
            } else {
                let new_block = try!(self.allocate(length));
                try!(self.insert_blocks(new_block, length, block));
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    fn node_blocks(&mut self, block: u64, mut offset: usize, mut len: usize, blocks: &mut Vec<u64>) -> Result<()> {
        if block == 0 {
            return Err(Error::new(ENOENT));
        }

        let node = try!(self.node(block));
        for extent in node.1.extents.iter() {
            for i in 0 .. extent.length {
                if offset == 0 {
                    if len > 0 {
                        blocks.push(extent.block + i);
                        len -= 1;
                    } else {
                        return Ok(())
                    }
                } else {
                    offset -= 1;
                }
            }
        }

        if offset > 0 || len > 0 {
            self.node_blocks(node.1.next, offset, len, blocks)
        } else {
            Ok(())
        }
    }

    pub fn read_node(&mut self, block: u64, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let block_offset = offset / 512;
        let byte_offset = offset % 512;
        let block_len = (buf.len() + byte_offset + 511)/512;

        let mut blocks = Vec::new();
        try!(self.node_blocks(block, block_offset, block_len, &mut blocks));

        let mut i = 0;
        for &block in blocks.iter() {
            let mut sector = ['r' as u8; 512];
            try!(self.disk.read_at(block, &mut sector));
            i += 512;
        }

        Ok(i)
    }

    pub fn write_node(&mut self, block: u64, offset: usize, buf: &[u8]) -> Result<usize> {
        let block_offset = offset / 512;
        let byte_offset = offset % 512;
        let block_len = (buf.len() + byte_offset + 511)/512;

        try!(self.node_ensure_len(block, (block_offset + block_len) as u64));

        let mut blocks = Vec::new();
        try!(self.node_blocks(block, block_offset, block_len, &mut blocks));

        let mut i = 0;
        for &block in blocks.iter() {
            let sector = ['w' as u8; 512];
            try!(self.disk.write_at(block, &sector));
            i += 512;
        }

        Ok(i)
    }
}
