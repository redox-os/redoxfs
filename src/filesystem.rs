use std::cmp::min;

use syscall::error::{Result, Error, EEXIST, EISDIR, ENOENT, ENOSPC, ENOTDIR, ENOTEMPTY};

use super::{Disk, ExNode, Extent, Header, Node};

/// A file system
pub struct FileSystem {
    pub disk: Box<Disk>,
    pub block: u64,
    pub header: (u64, Header)
}

impl FileSystem {
    /// Open a file system on a disk
    pub fn open(mut disk: Box<Disk>) -> Result<Self> {
        for block in 0..65536 {
            let mut header = (0, Header::default());
            try!(disk.read_at(block + header.0, &mut header.1));

            if header.1.valid() {
                let mut root = (header.1.root, Node::default());
                try!(disk.read_at(block + root.0, &mut root.1));

                let mut free = (header.1.free, Node::default());
                try!(disk.read_at(block + free.0, &mut free.1));

                return Ok(FileSystem {
                    disk: disk,
                    block: block,
                    header: header
                });
            }
        }

        Err(Error::new(ENOENT))
    }

    /// Create a file system on a disk
    pub fn create(mut disk: Box<Disk>) -> Result<Self> {
        let size = try!(disk.size());

        if size >= 4 * 512 {
            let mut free = (2, Node::new(Node::MODE_FILE, "free", 0));
            free.1.extents[0] = Extent::new(4, size - 4 * 512);
            try!(disk.write_at(free.0, &free.1));

            let root = (1, Node::new(Node::MODE_DIR | 0o755, "root", 0));
            try!(disk.write_at(root.0, &root.1));

            let header = (0, Header::new(size, root.0, free.0));
            try!(disk.write_at(header.0, &header.1));

            Ok(FileSystem {
                disk: disk,
                block: 0,
                header: header
            })
        } else {
            Err(Error::new(ENOSPC))
        }
    }

    pub fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        self.disk.read_at(self.block + block, buffer)
    }

    pub fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        self.disk.write_at(self.block + block, buffer)
    }

    pub fn allocate(&mut self, length: u64) -> Result<u64> {
        //TODO: traverse next pointer
        let free_block = self.header.1.free;
        let mut free = try!(self.node(free_block));
        let mut block_option = None;
        for mut extent in free.1.extents.iter_mut() {
            if extent.length/512 >= length {
                block_option = Some(extent.block);
                extent.length -= length * 512;
                extent.block += length;
                break;
            }
        }
        if let Some(block) = block_option {
            try!(self.write_at(free.0, &free.1));
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
        try!(self.read_at(block, &mut node));
        Ok((block, node))
    }

    pub fn ex_node(&mut self, block: u64) -> Result<(u64, ExNode)> {
        let mut node = ExNode::default();
        try!(self.read_at(block, &mut node));
        Ok((block, node))
    }

    pub fn child_nodes(&mut self, children: &mut Vec<(u64, Node)>, parent_block: u64) -> Result<()> {
        if parent_block == 0 {
            return Ok(());
        }

        let parent = try!(self.node(parent_block));
        for extent in parent.1.extents.iter() {
            for (block, size) in extent.blocks() {
                if size >= 512 {
                    children.push(try!(self.node(block)));
                }
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
            for (block, size) in extent.blocks() {
                if size >= 512 {
                    let child = try!(self.node(block));

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
        }

        self.find_node(name, parent.1.next)
    }

    pub fn path_nodes(&mut self, path: &str, nodes: &mut Vec<(u64, Node)>) -> Result<(u64, Node)> {
        let mut block = self.header.1.root;
        nodes.push(try!(self.node(block)));

        for part in path.split('/') {
            if ! part.is_empty() {
                let node = try!(self.find_node(part, block));
                block = node.0;
                nodes.push(node);
            }
        }

        Ok(nodes.pop().unwrap())
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
            } else if length % 512 == 0 && extent.block == block + length/512 {
                //At beginning
                inserted = true;
                extent.block = block;
                extent.length += length;
                break;
            } else if extent.length % 512 == 0 && extent.block + extent.length/512 == block {
                //At end
                inserted = true;
                extent.length += length;
                break;
            }
        }

        if inserted {
            try!(self.write_at(parent.0, &parent.1));
            Ok(())
        } else {
            if parent.1.next == 0 {
                parent.1.next = try!(self.allocate(1));
                try!(self.write_at(parent.0, &parent.1));
                try!(self.write_at(parent.1.next, &Node::default()));
            }

            self.insert_blocks(block, length, parent.1.next)
        }
    }

    pub fn create_node(&mut self, mode: u16, name: &str, parent_block: u64) -> Result<(u64, Node)> {
        if self.find_node(name, parent_block).is_ok() {
            Err(Error::new(EEXIST))
        } else {
            let node = (try!(self.allocate(1)), Node::new(mode, name, parent_block));
            try!(self.write_at(node.0, &node.1));

            try!(self.insert_blocks(node.0, 512, parent_block));

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
            if block >= extent.block && block + length <= extent.block + extent.length/512 {
                //Inside
                removed = true;

                let left = Extent::new(extent.block, (block - extent.block) * 512);
                let right = Extent::new(block + length, ((extent.block + extent.length/512) - (block + length)) * 512);

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
            try!(self.write_at(parent.0, &parent.1));

            if let Some(replace) = replace_option {
                try!(self.insert_blocks(replace.block, replace.length, parent_block));
            }

            try!(self.deallocate(block, 512));

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
            try!(self.write_at(node.0, &Node::default()));

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

        let mut changed = false;

        let mut node = try!(self.node(block));
        for mut extent in node.1.extents.iter_mut() {
            if extent.length >= length {
                length = 0;
                break;
            } else {
                changed = true;
                let allocated = ((extent.length + 511)/512) * 512;
                if allocated >= length {
                    extent.length = length;
                    length = 0;
                    break;
                } else {
                    extent.length = allocated;
                    length -= allocated;
                }
            }
        }

        if changed {
            try!(self.write_at(node.0, &node.1));
        }

        if length > 0 {
            if node.1.next > 0 {
                self.node_ensure_len(node.1.next, length)
            } else {
                let new_block = try!(self.allocate((length + 511)/512));
                try!(self.insert_blocks(new_block, length, block));
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    pub fn node_set_len(&mut self, block: u64, mut length: u64) -> Result<()> {
        if block == 0 {
            return Err(Error::new(ENOENT));
        }

        let mut changed = false;

        let mut node = try!(self.node(block));
        for mut extent in node.1.extents.iter_mut() {
            if extent.length > length {
                //TODO: try!(self.deallocate(block, 512));
                extent.length = length;
                changed = true;
                length = 0;
            } else {
                length -= extent.length;
            }
        }

        if changed {
            try!(self.write_at(node.0, &node.1));
        }

        if node.1.next > 0 {
            self.node_set_len(node.1.next, length)
        } else {
            Ok(())
        }
    }

    fn node_extents(&mut self, block: u64, mut offset: u64, mut len: usize, extents: &mut Vec<Extent>) -> Result<()> {
        if block == 0 {
            return Ok(());
        }

        let node = try!(self.node(block));
        for extent in node.1.extents.iter() {
            let mut push_extent = Extent::default();
            for (block, size) in extent.blocks() {
                if offset == 0 {
                    if push_extent.block == 0 {
                        push_extent.block = block;
                    }
                    if len >= size {
                        push_extent.length += size as u64;
                        len -= size;
                    } else if len > 0 {
                        push_extent.length += len as u64;
                        len = 0;
                        break;
                    } else {
                        break;
                    }
                } else {
                    offset -= 1;
                }
            }
            if push_extent.length > 0 {
                extents.push(push_extent);
            }
            if len == 0 {
                break;
            }
        }

        if len > 0 {
            self.node_extents(node.1.next, offset, len, extents)
        } else {
            Ok(())
        }
    }

    pub fn read_node(&mut self, block: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let block_offset = offset / 512;
        let mut byte_offset = (offset % 512) as usize;

        let mut extents = Vec::new();
        try!(self.node_extents(block, block_offset, byte_offset + buf.len(), &mut extents));

        let mut i = 0;
        for extent in extents.iter() {
            let mut block = extent.block;
            let mut length = extent.length;

            if byte_offset > 0 && length > 0 {
                let mut sector = [0; 512];
                try!(self.read_at(block, &mut sector));

                let sector_size = min(sector.len() as u64, length) as usize;
                for (s_b, mut b) in sector[byte_offset..sector_size].iter().zip(buf[i..].iter_mut()) {
                    *b = *s_b;
                    i += 1;
                }

                block += 1;
                length -= sector_size as u64;

                byte_offset = 0;
            }

            let length_aligned = ((min(length, (buf.len() - i) as u64)/512) * 512) as usize;

            if length_aligned > 0 {
                let extent_buf = &mut buf[i..i + length_aligned];
                try!(self.read_at(block, extent_buf));
                i += length_aligned;
                block += (length_aligned as u64)/512;
                length -= length_aligned as u64;
            }

            if length > 0 {
                let mut sector = [0; 512];
                try!(self.read_at(block, &mut sector));

                let sector_size = min(sector.len() as u64, length) as usize;
                for (s_b, mut b) in sector[..sector_size].iter().zip(buf[i..].iter_mut()) {
                    *b = *s_b;
                    i += 1;
                }

                block += 1;
                length -= sector_size as u64;
            }

            assert_eq!(length, 0);
            assert_eq!(block, extent.block + (extent.length + 511)/512);
        }

        Ok(i)
    }

    pub fn write_node(&mut self, block: u64, offset: u64, buf: &[u8]) -> Result<usize> {
        let block_offset = offset / 512;
        let mut byte_offset = (offset % 512) as usize;

        try!(self.node_ensure_len(block, block_offset as u64 * 512 + (byte_offset + buf.len()) as u64));

        let mut extents = Vec::new();
        try!(self.node_extents(block, block_offset, byte_offset + buf.len(), &mut extents));

        let mut i = 0;
        for extent in extents.iter() {
            let mut block = extent.block;
            let mut length = extent.length;

            if byte_offset > 0 && length > 0 {
                let mut sector = [0; 512];
                try!(self.read_at(block, &mut sector));

                let sector_size = min(sector.len() as u64, length) as usize;
                for (mut s_b, b) in sector[byte_offset..sector_size].iter_mut().zip(buf[i..].iter()) {
                    *s_b = *b;
                    i += 1;
                }

                try!(self.write_at(block, &sector));

                block += 1;
                length -= sector_size as u64;

                byte_offset = 0;
            }

            let length_aligned = ((min(length, (buf.len() - i) as u64)/512) * 512) as usize;

            if length_aligned > 0 {
                let extent_buf = &buf[i..i + length_aligned];
                try!(self.write_at(block, extent_buf));
                i += length_aligned;
                block += (length_aligned as u64)/512;
                length -= length_aligned as u64;
            }

            if length > 0 {
                let mut sector = [0; 512];
                try!(self.read_at(block, &mut sector));

                let sector_size = min(sector.len() as u64, length) as usize;
                for (mut s_b, b) in sector[..sector_size].iter_mut().zip(buf[i..].iter()) {
                    *s_b = *b;
                    i += 1;
                }

                try!(self.write_at(block, &sector));

                block += 1;
                length -= sector_size as u64;
            }

            assert_eq!(length, 0);
            assert_eq!(block, extent.block + (extent.length + 511)/512);
        }

        Ok(i)
    }

    pub fn node_len(&mut self, block: u64) -> Result<u64> {
        if block == 0 {
            return Err(Error::new(ENOENT));
        }

        let mut size = 0;

        let node = try!(self.node(block));
        for extent in node.1.extents.iter() {
            size += extent.length;
        }

        if node.1.next > 0 {
            size += try!(self.node_len(node.1.next));
            Ok(size)
        } else {
            Ok(size)
        }
    }
}
