use core::{mem, ops, slice, str};

use crate::{BlockLevel, BlockTrait, Node, TreePtr, BLOCK_SIZE, DIR_ENTRY_MAX_LENGTH};

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct DirEntry {
    node_ptr: TreePtr<Node>,
    name: [u8; DIR_ENTRY_MAX_LENGTH],
}

impl DirEntry {
    pub fn new(node_ptr: TreePtr<Node>, name: &str) -> DirEntry {
        let mut entry = DirEntry {
            node_ptr,
            ..Default::default()
        };

        entry.name[..name.len()].copy_from_slice(name.as_bytes());

        entry
    }

    pub fn node_ptr(&self) -> TreePtr<Node> {
        self.node_ptr
    }

    fn name_len(&self) -> usize {
        let mut len = 0;
        while len < self.name.len() {
            if self.name[len] == 0 {
                break;
            }
            len += 1;
        }
        len
    }

    pub fn name(&self) -> Option<&str> {
        let len = self.name_len();
        //TODO: report utf8 error?
        str::from_utf8(&self.name[..len]).ok()
    }

    // 4 bytes TreePtr
    // 1 byte name_len
    const SERIALIZED_PREFIX_SIZE: usize = mem::size_of::<TreePtr<Node>>() + 1;

    pub fn serialized_size(&self) -> usize {
        DirEntry::SERIALIZED_PREFIX_SIZE + self.name_len()
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Option<usize> {
        let required = self.serialized_size();
        if buf.len() < required {
            return None;
        }

        buf[0..4].copy_from_slice(&self.node_ptr().to_bytes());
        buf[4] = self.name_len() as u8;
        buf[5..5 + self.name_len()].copy_from_slice(&self.name[..self.name_len()]);

        Some(required)
    }

    fn deserialize_from(buf: &[u8]) -> Result<(Self, usize), &'static str> {
        if buf.len() <= DirEntry::SERIALIZED_PREFIX_SIZE {
            return Err("Buffer too small");
        }

        let node_ptr: TreePtr<Node> =
            TreePtr::from_bytes(buf[0..4].try_into().expect("Slice must be 4 bytes long"));
        let name_len = buf[4] as usize;

        if name_len < 1 || name_len > DIR_ENTRY_MAX_LENGTH {
            return Err("Invalid name length");
        }

        if buf.len() < DirEntry::SERIALIZED_PREFIX_SIZE + name_len {
            return Err("Buffer too small");
        }

        let mut name = [0u8; DIR_ENTRY_MAX_LENGTH];
        name[..name_len].copy_from_slice(
            &buf[DirEntry::SERIALIZED_PREFIX_SIZE..DirEntry::SERIALIZED_PREFIX_SIZE + name_len],
        );

        Ok((
            DirEntry { node_ptr, name },
            DirEntry::SERIALIZED_PREFIX_SIZE + name_len,
        ))
    }
}

impl Default for DirEntry {
    fn default() -> Self {
        Self {
            node_ptr: TreePtr::default(),
            name: [0; DIR_ENTRY_MAX_LENGTH],
        }
    }
}

pub struct DirList {
    count: u16,
    entry_bytes_len: u16,
    entry_bytes: [u8; BLOCK_SIZE as usize - 4],
}

unsafe impl BlockTrait for DirList {
    fn empty(level: BlockLevel) -> Option<Self> {
        if level.0 == 0 {
            Some(Self {
                count: 0,
                entry_bytes_len: 0,
                entry_bytes: [0; BLOCK_SIZE as usize - 4],
            })
        } else {
            None
        }
    }
}

impl DirList {
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn entries(&self) -> DirEntryIterator {
        DirEntryIterator {
            dir_list: self,
            emit_count: 0,
            position: 0,
        }
    }

    fn entry_position_for_name(&self, name: &str) -> Option<usize> {
        let name_len = name.len();
        let mut position = 0;
        let mut entry_id = 0;

        while entry_id < self.count {
            let entry_name_len = self.entry_bytes[position + 4] as usize;
            if entry_name_len == name_len {
                let start = DirEntry::SERIALIZED_PREFIX_SIZE + position;
                let entry_name = &self.entry_bytes[start..start + entry_name_len];
                if entry_name == name.as_bytes() {
                    return Some(position);
                }
            }
            position += DirEntry::SERIALIZED_PREFIX_SIZE + entry_name_len;
            entry_id += 1;
        }
        None
    }

    pub fn find_entry(&self, name: &str) -> Option<DirEntry> {
        if let Some(position) = self.entry_position_for_name(name) {
            let (entry, _) = DirEntry::deserialize_from(&self.entry_bytes[position..]).unwrap();
            return Some(entry);
        }
        None
    }

    pub fn remove_entry(&mut self, name: &str) -> bool {
        if let Some(position) = self.entry_position_for_name(name) {
            let entry_size =
                DirEntry::SERIALIZED_PREFIX_SIZE + self.entry_bytes[position + 4] as usize;
            let remaining_size = self.entry_bytes_len as usize - position - entry_size;
            if remaining_size > 0 {
                self.entry_bytes.copy_within(
                    position + entry_size..self.entry_bytes_len as usize,
                    position,
                );
            }
            self.entry_bytes_len -= entry_size as u16;
            self.count -= 1;
            return true;
        }
        false
    }

    pub fn for_each_entry<F>(&self, mut f: F)
    where
        F: FnMut(&[u8; 4], &[u8]),
    {
        let mut position = 0;
        let mut entry_id = 0;

        while entry_id < self.count {
            let node_ptr_bytes = &self.entry_bytes[position..position + 4];
            //let node_ptr = TreePtr::<Node>::from_bytes(node_ptr_bytes.try_into().unwrap());
            let entry_name_len = self.entry_bytes[position + 4] as usize;
            let start = DirEntry::SERIALIZED_PREFIX_SIZE + position;
            let entry_name = &self.entry_bytes[start..start + entry_name_len];

            f(node_ptr_bytes.try_into().unwrap(), entry_name);

            position += DirEntry::SERIALIZED_PREFIX_SIZE + entry_name_len;
            entry_id += 1;
        }
    }

    pub fn append(&mut self, entry: &DirEntry) -> bool {
        let entry_bytes_len = self.entry_bytes_len as usize;
        if let Some(size) = entry.serialize_into(&mut self.entry_bytes[entry_bytes_len..]) {
            self.count += 1;
            self.entry_bytes_len += size as u16;
            return true;
        }
        false
    }

    pub fn entry_count(&self) -> usize {
        self.count as usize
    }
}

impl ops::Deref for DirList {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const DirList as *const u8,
                mem::size_of::<DirList>(),
            ) as &[u8]
        }
    }
}

impl ops::DerefMut for DirList {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(self as *mut DirList as *mut u8, mem::size_of::<DirList>())
                as &mut [u8]
        }
    }
}

pub struct DirEntryIterator<'a> {
    dir_list: &'a DirList,
    emit_count: usize,
    position: usize,
}

impl Iterator for DirEntryIterator<'_> {
    type Item = DirEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.emit_count < self.dir_list.entry_count() {
            let position = self.position;
            let (entry, bytes_read) =
                DirEntry::deserialize_from(&self.dir_list.entry_bytes[position..]).unwrap();

            self.emit_count += 1;
            self.position += bytes_read;

            Some(entry)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;

    #[test]
    fn dir_list_size_test() {
        use core::ops::Deref;
        assert_eq!(
            DirList::empty(BlockLevel(0)).unwrap().deref().len(),
            BLOCK_SIZE as usize
        );
    }

    #[test]
    fn test_append() {
        let mut dir_list = DirList::empty(BlockLevel(0)).unwrap();
        let dirent = DirEntry::new(TreePtr::new(123), "test000");

        assert!(dir_list.append(&dirent));
        assert_eq!(dir_list.entry_count(), 1);
        assert_eq!(dir_list.entry_bytes_len as usize, dirent.serialized_size());

        let max_entries = dir_list.entry_bytes.len() / dirent.serialized_size();
        for i in 1..max_entries {
            let dirent = DirEntry::new(TreePtr::new(123), format!("test{i:03}").as_str());
            assert!(dir_list.append(&dirent), "Failed on iteration {i}");
        }
        let dirent = DirEntry::new(TreePtr::new(123), format!("test{max_entries}").as_str());
        assert!(!dir_list.append(&dirent));

        for (i, entry) in dir_list.entries().enumerate() {
            assert_eq!(entry.name().unwrap(), format!("test{i:03}"));
        }
    }
}
