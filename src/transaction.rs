use alloc::{
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};
use core::{
    cmp::min,
    mem,
    ops::{Deref, DerefMut},
};
use syscall::error::{
    Error, Result, EEXIST, EINVAL, EIO, EISDIR, ENOENT, ENOSPC, ENOTDIR, ENOTEMPTY, ERANGE,
};

use crate::{
    AllocEntry, AllocList, Allocator, BlockData, BlockPtr, BlockRaw, DirEntry, DirList, Disk,
    FileSystem, Header, Node, NodeLevel, TreeData, TreePtr, ALLOC_LIST_ENTRIES, BLOCK_SIZE,
    HEADER_RING,
};

pub struct Transaction<'a, D: Disk> {
    fs: &'a mut FileSystem<D>,
    //TODO: make private
    pub header: Header,
    //TODO: make private
    pub header_changed: bool,
    allocator: Allocator,
    allocator_log: VecDeque<AllocEntry>,
    deallocate: Vec<u64>,
    write_cache: BTreeMap<u64, BlockRaw>,
}

impl<'a, D: Disk> Transaction<'a, D> {
    pub(crate) fn new(fs: &'a mut FileSystem<D>) -> Self {
        let header = fs.header.clone();
        let allocator = fs.allocator.clone();
        Self {
            fs,
            header,
            header_changed: false,
            allocator,
            allocator_log: VecDeque::new(),
            deallocate: Vec::new(),
            write_cache: BTreeMap::new(),
        }
    }

    pub fn commit(mut self, squash: bool) -> Result<()> {
        self.sync(squash)?;
        self.fs.header = self.header;
        self.fs.allocator = self.allocator;
        Ok(())
    }

    // Unsafe because order must be done carefully and changes must be flushed to disk
    unsafe fn allocate(&mut self) -> Result<u64> {
        match self.allocator.allocate() {
            Some(addr) => {
                self.allocator_log.push_back(AllocEntry::new(addr, -1));
                Ok(addr)
            }
            None => Err(Error::new(ENOSPC)),
        }
    }

    // Unsafe because order must be done carefully and changes must be flushed to disk
    unsafe fn deallocate(&mut self, addr: u64) {
        //TODO: should we use some sort of not-null abstraction?
        assert!(addr != 0);

        // Remove from write_cache if it is there, since it no longer needs to be written
        self.write_cache.remove(&addr);

        // Search and remove the last matching entry in allocator_log
        let mut found = false;
        for i in (0..self.allocator_log.len()).rev() {
            let entry = self.allocator_log[i];
            if entry.addr() == addr && entry.count() == -1 {
                found = true;
                self.allocator_log.remove(i);
                break;
            }
        }

        if found {
            // Deallocate immediately since it is an allocation that was not needed
            self.allocator.deallocate(addr);
        } else {
            // Deallocate later when syncing filesystem, to avoid re-use
            self.deallocate.push(addr);
        }
    }

    fn deallocate_block<T>(&mut self, ptr: BlockPtr<T>) {
        if !ptr.is_null() {
            unsafe {
                self.deallocate(ptr.addr());
            }
        }
    }

    fn sync_allocator(&mut self, squash: bool) -> Result<bool> {
        let mut prev_ptr = BlockPtr::default();
        if squash {
            // Clear and rebuild alloc log
            self.allocator_log.clear();
            let levels = self.allocator.levels();
            for level in (0..levels.len()).rev() {
                let count = (1 << level) as i64;
                'addrs: for &addr in levels[level].iter() {
                    for entry in self.allocator_log.iter_mut() {
                        if addr + count as u64 == entry.addr() {
                            // New entry is at start of existing entry
                            *entry = AllocEntry::new(addr, count + entry.count());
                            continue 'addrs;
                        } else if entry.addr() + entry.count() as u64 == addr {
                            // New entry is at end of existing entry
                            *entry = AllocEntry::new(entry.addr(), entry.count() + count);
                            continue 'addrs;
                        }
                    }

                    self.allocator_log.push_back(AllocEntry::new(addr, count));
                }
            }

            // Prepare to deallocate old alloc blocks
            let mut alloc_ptr = self.header.alloc;
            while !alloc_ptr.is_null() {
                let alloc = self.read_block(alloc_ptr)?;
                self.deallocate_block(alloc_ptr);
                alloc_ptr = alloc.data().prev;
            }
        } else {
            // Return if there are no log changes
            if self.allocator_log.is_empty() && self.deallocate.is_empty() {
                return Ok(false);
            }

            // Push old alloc block to front of allocator log
            //TODO: just skip this if it is already full?
            let alloc = self.read_block(self.header.alloc)?;
            for i in (0..alloc.data().entries.len()).rev() {
                let entry = alloc.data().entries[i];
                if !entry.is_null() {
                    self.allocator_log.push_front(entry);
                }
            }

            // Prepare to deallocate old alloc block
            unsafe {
                self.deallocate(alloc.addr());
            }

            // Link to previous alloc block
            prev_ptr = alloc.data().prev;
        }

        // Allocate required blocks, including CoW of current alloc tail
        let mut new_blocks = Vec::new();
        while new_blocks.len() * ALLOC_LIST_ENTRIES
            <= self.allocator_log.len() + self.deallocate.len()
        {
            new_blocks.push(unsafe { self.allocate()? });
        }

        // De-allocate old blocks (after allocation to prevent re-use)
        //TODO: optimize allocator log in memory
        while let Some(addr) = self.deallocate.pop() {
            self.allocator.deallocate(addr);
            self.allocator_log.push_back(AllocEntry::new(addr, 1));
        }

        for new_block in new_blocks {
            let mut alloc = BlockData::new(new_block, AllocList::default());
            alloc.data_mut().prev = prev_ptr;
            for entry in alloc.data_mut().entries.iter_mut() {
                if let Some(log_entry) = self.allocator_log.pop_front() {
                    *entry = log_entry;
                } else {
                    break;
                }
            }
            prev_ptr = unsafe { self.write_block(alloc)? };
        }

        self.header.alloc = prev_ptr;
        self.header_changed = true;

        Ok(true)
    }

    //TODO: change this function, provide another way to squash, only write header in commit
    pub fn sync(&mut self, squash: bool) -> Result<bool> {
        // Make sure alloc is synced
        self.sync_allocator(squash)?;

        // Write all items in write cache
        for (addr, raw) in self.write_cache.iter_mut() {
            assert!(self.header_changed);
            self.fs.encrypt(raw);
            let count = unsafe { self.fs.disk.write_at(self.fs.block + addr, &raw)? };
            if count != mem::size_of::<BlockRaw>() {
                // Read wrong number of bytes
                log::error!("SYNC WRITE_CACHE: WRONG NUMBER OF BYTES");
                return Err(Error::new(EIO));
            }
        }
        self.write_cache.clear();

        if !self.header_changed {
            return Ok(false);
        }

        // Update header to next generation
        let gen = self.header.update(self.fs.aes_opt.as_ref());
        let gen_block = gen % HEADER_RING;

        // Write header
        let count = unsafe {
            self.fs
                .disk
                .write_at(self.fs.block + gen_block, &self.header)?
        };
        if count != mem::size_of_val(&self.header) {
            // Read wrong number of bytes
            log::error!("SYNC: WRONG NUMBER OF BYTES");
            return Err(Error::new(EIO));
        }

        self.header_changed = false;
        Ok(true)
    }

    pub fn read_block<T: Default + DerefMut<Target = [u8]>>(
        &mut self,
        ptr: BlockPtr<T>,
    ) -> Result<BlockData<T>> {
        if ptr.is_null() {
            // Pointer is invalid (should this return None?)
            log::error!("READ_BLOCK: POINTER IS NULL");
            return Err(Error::new(ENOENT));
        }

        let mut data = T::default();
        if let Some(raw) = self.write_cache.get(&ptr.addr()) {
            data.copy_from_slice(raw);
        } else {
            let count = unsafe {
                self.fs
                    .disk
                    .read_at(self.fs.block + ptr.addr(), &mut data)?
            };
            if count != mem::size_of::<T>() {
                // Read wrong number of bytes
                log::error!("READ_BLOCK: WRONG NUMBER OF BYTES");
                return Err(Error::new(EIO));
            }
            self.fs.decrypt(&mut data);
        }

        let block = BlockData::new(ptr.addr(), data);
        let block_ptr = block.create_ptr();
        if block_ptr.hash() != ptr.hash() {
            // Incorrect hash
            log::error!(
                "READ_BLOCK: INCORRECT HASH {} != {} for block {}",
                block_ptr.hash(),
                ptr.hash(),
                ptr.addr()
            );
            return Err(Error::new(EIO));
        }
        Ok(block)
    }

    /// Read block data or, if pointer is null, return default block data
    ///
    /// # Safety
    /// Unsafe because it creates strange BlockData types that must be swapped before use
    unsafe fn read_block_or_default<T: Default + DerefMut<Target = [u8]>>(
        &mut self,
        ptr: BlockPtr<T>,
    ) -> Result<BlockData<T>> {
        if ptr.is_null() {
            Ok(BlockData::new(0, T::default()))
        } else {
            self.read_block(ptr)
        }
    }

    /// Write block data to a new address, returning new address
    pub fn sync_block<T: Deref<Target = [u8]>>(
        &mut self,
        mut block: BlockData<T>,
    ) -> Result<BlockPtr<T>> {
        // Swap block to new address
        let old_addr = block.swap_addr(unsafe { self.allocate()? });
        // Deallocate old address (will only take effect after sync_allocator, which helps to
        // prevent re-use before a new header is written
        if old_addr != 0 {
            unsafe {
                self.deallocate(old_addr);
            }
        }
        // Write new block
        unsafe { self.write_block(block) }
    }

    /// Write block data, returning a calculated block pointer
    ///
    /// # Safety
    /// Unsafe to encourage CoW semantics
    pub(crate) unsafe fn write_block<T: Deref<Target = [u8]>>(
        &mut self,
        block: BlockData<T>,
    ) -> Result<BlockPtr<T>> {
        if block.addr() == 0 {
            // Pointer is invalid
            log::error!("WRITE_BLOCK: POINTER IS NULL");
            return Err(Error::new(ENOENT));
        }

        //TODO: transmute?
        let mut raw = BlockRaw::default();
        raw.copy_from_slice(block.data());
        self.write_cache.insert(block.addr(), raw);

        Ok(block.create_ptr())
    }

    pub fn read_tree<T: Default + DerefMut<Target = [u8]>>(
        &mut self,
        ptr: TreePtr<T>,
    ) -> Result<TreeData<T>> {
        if ptr.is_null() {
            // ID is invalid (should this return None?)
            log::error!("READ_TREE: ID IS NULL");
            return Err(Error::new(ENOENT));
        }

        let (i3, i2, i1, i0) = ptr.indexes();
        let l3 = self.read_block(self.header.tree)?;
        let l2 = self.read_block(l3.data().ptrs[i3])?;
        let l1 = self.read_block(l2.data().ptrs[i2])?;
        let l0 = self.read_block(l1.data().ptrs[i1])?;
        let raw = self.read_block(l0.data().ptrs[i0])?;

        //TODO: transmute instead of copy?
        let mut data = T::default();
        data.copy_from_slice(raw.data());

        Ok(TreeData::new(ptr.id(), data))
    }

    //TODO: improve performance, reduce writes
    pub fn insert_tree<T: Deref<Target = [u8]>>(
        &mut self,
        block_ptr: BlockPtr<T>,
    ) -> Result<TreePtr<T>> {
        // Remember that if there is a free block at any level it will always sync when it
        // allocates at the lowest level, so we can save a write by not writing each level as it
        // is allocated.
        unsafe {
            let mut l3 = self.read_block(self.header.tree)?;
            for i3 in 0..l3.data().ptrs.len() {
                let mut l2 = self.read_block_or_default(l3.data().ptrs[i3])?;
                for i2 in 0..l2.data().ptrs.len() {
                    let mut l1 = self.read_block_or_default(l2.data().ptrs[i2])?;
                    for i1 in 0..l1.data().ptrs.len() {
                        let mut l0 = self.read_block_or_default(l1.data().ptrs[i1])?;
                        for i0 in 0..l0.data().ptrs.len() {
                            let pn = l0.data().ptrs[i0];

                            // Skip if already in use
                            if !pn.is_null() {
                                continue;
                            }

                            let tree_ptr = TreePtr::from_indexes((i3, i2, i1, i0));

                            // Skip if this is a reserved node (null)
                            if tree_ptr.is_null() {
                                continue;
                            }

                            // Write updates to newly allocated blocks
                            l0.data_mut().ptrs[i0] = block_ptr.cast();
                            l1.data_mut().ptrs[i1] = self.sync_block(l0)?;
                            l2.data_mut().ptrs[i2] = self.sync_block(l1)?;
                            l3.data_mut().ptrs[i3] = self.sync_block(l2)?;
                            self.header.tree = self.sync_block(l3)?;
                            self.header_changed = true;

                            return Ok(tree_ptr);
                        }
                    }
                }
            }
        }

        Err(Error::new(ENOSPC))
    }

    pub fn sync_trees<T: Deref<Target = [u8]>>(&mut self, nodes: &[TreeData<T>]) -> Result<()> {
        for node in nodes.iter().rev() {
            let ptr = node.ptr();
            if ptr.is_null() {
                // ID is invalid
                log::error!("SYNC_TREE: ID IS NULL");
                return Err(Error::new(ENOENT));
            }
        }

        for node in nodes.iter().rev() {
            let (i3, i2, i1, i0) = node.ptr().indexes();
            let mut l3 = self.read_block(self.header.tree)?;
            let mut l2 = self.read_block(l3.data().ptrs[i3])?;
            let mut l1 = self.read_block(l2.data().ptrs[i2])?;
            let mut l0 = self.read_block(l1.data().ptrs[i1])?;
            let mut raw = self.read_block(l0.data().ptrs[i0])?;

            // Return if data is equal
            if raw.data().deref() == node.data().deref() {
                continue;
            }

            //TODO: transmute instead of copy?
            raw.data_mut().copy_from_slice(node.data());

            // Write updates to newly allocated blocks
            l0.data_mut().ptrs[i0] = self.sync_block(raw)?;
            l1.data_mut().ptrs[i1] = self.sync_block(l0)?;
            l2.data_mut().ptrs[i2] = self.sync_block(l1)?;
            l3.data_mut().ptrs[i3] = self.sync_block(l2)?;
            self.header.tree = self.sync_block(l3)?;
            self.header_changed = true;
        }

        Ok(())
    }

    pub fn sync_tree<T: Deref<Target = [u8]>>(&mut self, node: TreeData<T>) -> Result<()> {
        self.sync_trees(&[node])
    }

    //TODO: use more efficient methods for reading directories
    pub fn child_nodes(
        &mut self,
        parent_ptr: TreePtr<Node>,
        children: &mut Vec<DirEntry>,
    ) -> Result<()> {
        let parent = self.read_tree(parent_ptr)?;
        for block_offset in 0..(parent.data().size() / BLOCK_SIZE) {
            let block_ptr = self.node_block_ptr(&parent, block_offset)?;
            let dir_ptr: BlockPtr<DirList> = unsafe { block_ptr.cast() };
            let dir = self.read_block(dir_ptr)?;
            for entry in dir.data().entries {
                let node_ptr = entry.node_ptr();

                // Skip empty entries
                if node_ptr.is_null() {
                    continue;
                }

                children.push(entry);
            }
        }

        Ok(())
    }

    //TODO: improve performance (h-tree?)
    pub fn find_node(&mut self, parent_ptr: TreePtr<Node>, name: &str) -> Result<TreeData<Node>> {
        let parent = self.read_tree(parent_ptr)?;
        for block_offset in 0..(parent.data().size() / BLOCK_SIZE) {
            let block_ptr = self.node_block_ptr(&parent, block_offset)?;
            let dir_ptr: BlockPtr<DirList> = unsafe { block_ptr.cast() };
            let dir = self.read_block(dir_ptr)?;
            for entry in dir.data().entries {
                let node_ptr = entry.node_ptr();

                // Skip empty entries
                if node_ptr.is_null() {
                    continue;
                }

                // Return node pointer if name matches
                if let Some(entry_name) = entry.name() {
                    if entry_name == name {
                        //TODO: Do not require read of node
                        return self.read_tree(node_ptr);
                    }
                }
            }
        }

        Err(Error::new(ENOENT))
    }

    //TODO: improve performance (h-tree?)
    pub fn create_node(
        &mut self,
        parent_ptr: TreePtr<Node>,
        name: &str,
        mode: u16,
        ctime: u64,
        ctime_nsec: u32,
    ) -> Result<TreeData<Node>> {
        if name.contains(':') {
            return Err(Error::new(EINVAL));
        }

        if self.find_node(parent_ptr, name).is_ok() {
            return Err(Error::new(EEXIST));
        }

        unsafe {
            let parent = self.read_tree(parent_ptr)?;
            let node_block_data = BlockData::new(
                self.allocate()?,
                Node::new(
                    mode,
                    parent.data().uid(),
                    parent.data().gid(),
                    ctime,
                    ctime_nsec,
                ),
            );
            let node_block_ptr = self.write_block(node_block_data)?;
            let node_ptr = self.insert_tree(node_block_ptr)?;

            self.link_node(parent_ptr, name, node_ptr)?;

            //TODO: do not re-read node
            self.read_tree(node_ptr)
        }
    }

    pub fn link_node(
        &mut self,
        parent_ptr: TreePtr<Node>,
        name: &str,
        node_ptr: TreePtr<Node>,
    ) -> Result<()> {
        if name.contains(':') {
            return Err(Error::new(EINVAL));
        }

        if self.find_node(parent_ptr, name).is_ok() {
            return Err(Error::new(EEXIST));
        }

        let mut parent = self.read_tree(parent_ptr)?;

        let mut node = self.read_tree(node_ptr)?;
        let links = node.data().links();
        node.data_mut().set_links(links + 1);

        let entry = DirEntry::new(node_ptr, name).ok_or(Error::new(EINVAL))?;

        let block_end = parent.data().size() / BLOCK_SIZE;
        for block_offset in 0..block_end {
            let mut dir_block_ptr = self.node_block_ptr(&parent, block_offset)?;
            let mut dir_ptr: BlockPtr<DirList> = unsafe { dir_block_ptr.cast() };
            let mut dir = self.read_block(dir_ptr)?;
            let mut dir_changed = false;
            for old_entry in dir.data_mut().entries.iter_mut() {
                // Skip filled entries
                if !old_entry.node_ptr().is_null() {
                    continue;
                }

                *old_entry = entry;
                dir_changed = true;
                break;
            }
            if dir_changed {
                dir_ptr = self.sync_block(dir)?;
                dir_block_ptr = unsafe { dir_ptr.cast() };

                self.sync_node_block_ptr(&mut parent, block_offset, dir_block_ptr)?;
                self.sync_trees(&[parent, node])?;

                return Ok(());
            }
        }

        // Append a new dirlist, with first entry set to new entry
        let mut dir = BlockData::new(unsafe { self.allocate()? }, DirList::default());
        dir.data_mut().entries[0] = entry;
        let dir_ptr = unsafe { self.write_block(dir)? };
        let dir_block_ptr: BlockPtr<BlockRaw> = unsafe { dir_ptr.cast() };

        self.sync_node_block_ptr(&mut parent, block_end, dir_block_ptr)?;
        parent.data_mut().set_size((block_end + 1) * BLOCK_SIZE);
        self.sync_trees(&[parent, node])?;

        Ok(())
    }

    pub fn remove_node(&mut self, parent_ptr: TreePtr<Node>, name: &str, mode: u16) -> Result<()> {
        let mut parent = self.read_tree(parent_ptr)?;
        let blocks = parent.data().size() / BLOCK_SIZE;
        for block_offset in 0..blocks {
            let mut dir_block_ptr = self.node_block_ptr(&parent, block_offset)?;
            let mut dir_ptr: BlockPtr<DirList> = unsafe { dir_block_ptr.cast() };
            let mut dir = self.read_block(dir_ptr)?;
            let mut node_opt = None;
            for entry in dir.data_mut().entries.iter_mut() {
                let node_ptr = entry.node_ptr();

                // Skip empty entries
                if node_ptr.is_null() {
                    continue;
                }

                // Check if name matches
                if let Some(entry_name) = entry.name() {
                    if entry_name == name {
                        // Read node and test type against requested type
                        let node = self.read_tree(node_ptr)?;
                        if node.data().mode() & Node::MODE_TYPE == mode {
                            if node.data().is_dir() && node.data().size() > 0 {
                                // Tried to remove directory that still has entries
                                return Err(Error::new(ENOTEMPTY));
                            }

                            // Save node and clear entry
                            node_opt = Some(node);
                            *entry = DirEntry::default();
                            break;
                        } else if node.data().is_dir() {
                            // Found directory instead of requested type
                            return Err(Error::new(EISDIR));
                        } else {
                            // Did not find directory when requested
                            return Err(Error::new(ENOTDIR));
                        }
                    }
                }
            }

            if let Some(mut node) = node_opt {
                let links = node.data().links();
                if links > 1 {
                    node.data_mut().set_links(links - 1);
                } else {
                    node.data_mut().set_links(0);
                    self.truncate_node_inner(&mut node, 0)?;
                }

                if block_offset == blocks - 1 && dir.data().is_empty() {
                    // Remove empty parent block, if it is at the end
                    self.remove_node_block_ptr(&mut parent, block_offset)?;
                    parent.data_mut().set_size(block_offset * BLOCK_SIZE);
                } else {
                    // Save new parent block
                    dir_ptr = self.sync_block(dir)?;
                    dir_block_ptr = unsafe { dir_ptr.cast() };
                    self.sync_node_block_ptr(&mut parent, block_offset, dir_block_ptr)?;
                }

                // Sync both parent and node at the same time
                self.sync_trees(&[parent, node])?;

                return Ok(());
            }
        }

        Err(Error::new(ENOENT))
    }

    pub fn rename_node(
        &mut self,
        orig_parent_ptr: TreePtr<Node>,
        orig_name: &str,
        new_parent_ptr: TreePtr<Node>,
        new_name: &str,
    ) -> Result<()> {
        let orig = self.find_node(orig_parent_ptr, orig_name)?;

        //TODO: only allow ENOENT as an error?
        if let Ok(new) = self.find_node(new_parent_ptr, new_name) {
            // Move to same name, return
            if new.id() == orig.id() {
                return Ok(());
            }

            // Remove new name
            self.remove_node(
                new_parent_ptr,
                new_name,
                new.data().mode() & Node::MODE_TYPE,
            )?;
        }

        // Link original file to new name
        self.link_node(new_parent_ptr, new_name, orig.ptr())?;

        // Remove original file
        self.remove_node(
            orig_parent_ptr,
            orig_name,
            orig.data().mode() & Node::MODE_TYPE,
        )?;

        Ok(())
    }

    fn node_block_ptr(
        &mut self,
        node: &TreeData<Node>,
        block_offset: u64,
    ) -> Result<BlockPtr<BlockRaw>> {
        match NodeLevel::new(block_offset).ok_or(Error::new(ERANGE))? {
            NodeLevel::L0(i0) => Ok(node.data().level0[i0]),
            NodeLevel::L1(i1, i0) => {
                let l0 = self.read_block(node.data().level1[i1])?;
                Ok(l0.data().ptrs[i0])
            }
            NodeLevel::L2(i2, i1, i0) => {
                let l1 = self.read_block(node.data().level2[i2])?;
                let l0 = self.read_block(l1.data().ptrs[i1])?;
                Ok(l0.data().ptrs[i0])
            }
            NodeLevel::L3(i3, i2, i1, i0) => {
                let l2 = self.read_block(node.data().level3[i3])?;
                let l1 = self.read_block(l2.data().ptrs[i2])?;
                let l0 = self.read_block(l1.data().ptrs[i1])?;
                Ok(l0.data().ptrs[i0])
            }
            NodeLevel::L4(i4, i3, i2, i1, i0) => {
                let l3 = self.read_block(node.data().level4[i4])?;
                let l2 = self.read_block(l3.data().ptrs[i3])?;
                let l1 = self.read_block(l2.data().ptrs[i2])?;
                let l0 = self.read_block(l1.data().ptrs[i1])?;
                Ok(l0.data().ptrs[i0])
            }
        }
    }

    fn remove_node_block_ptr(
        &mut self,
        node: &mut TreeData<Node>,
        block_offset: u64,
    ) -> Result<()> {
        match NodeLevel::new(block_offset).ok_or(Error::new(ERANGE))? {
            NodeLevel::L0(i0) => {
                self.deallocate_block(node.data_mut().level0[i0].clear());
            }
            NodeLevel::L1(i1, i0) => {
                let mut l0 = self.read_block(node.data().level1[i1])?;
                self.deallocate_block(l0.data_mut().ptrs[i0].clear());
                if l0.data().is_empty() {
                    self.deallocate_block(node.data_mut().level1[i1].clear());
                } else {
                    node.data_mut().level1[i1] = self.sync_block(l0)?;
                }
            }
            NodeLevel::L2(i2, i1, i0) => {
                let mut l1 = self.read_block(node.data().level2[i2])?;
                let mut l0 = self.read_block(l1.data().ptrs[i1])?;
                self.deallocate_block(l0.data_mut().ptrs[i0].clear());
                if l0.data().is_empty() {
                    self.deallocate_block(l1.data_mut().ptrs[i1].clear());
                } else {
                    l1.data_mut().ptrs[i1] = self.sync_block(l0)?;
                }
                if l1.data().is_empty() {
                    self.deallocate_block(node.data_mut().level2[i2].clear());
                } else {
                    node.data_mut().level2[i2] = self.sync_block(l1)?;
                }
            }
            NodeLevel::L3(i3, i2, i1, i0) => {
                let mut l2 = self.read_block(node.data().level3[i3])?;
                let mut l1 = self.read_block(l2.data().ptrs[i2])?;
                let mut l0 = self.read_block(l1.data().ptrs[i1])?;
                self.deallocate_block(l0.data_mut().ptrs[i0].clear());
                if l0.data().is_empty() {
                    self.deallocate_block(l1.data_mut().ptrs[i1].clear());
                } else {
                    l1.data_mut().ptrs[i1] = self.sync_block(l0)?;
                }
                if l1.data().is_empty() {
                    self.deallocate_block(l2.data_mut().ptrs[i2].clear());
                } else {
                    l2.data_mut().ptrs[i2] = self.sync_block(l1)?;
                }
                if l2.data().is_empty() {
                    self.deallocate_block(node.data_mut().level3[i3].clear());
                } else {
                    node.data_mut().level3[i3] = self.sync_block(l2)?;
                }
            }
            NodeLevel::L4(i4, i3, i2, i1, i0) => {
                let mut l3 = self.read_block(node.data().level4[i4])?;
                let mut l2 = self.read_block(l3.data().ptrs[i3])?;
                let mut l1 = self.read_block(l2.data().ptrs[i2])?;
                let mut l0 = self.read_block(l1.data().ptrs[i1])?;
                self.deallocate_block(l0.data_mut().ptrs[i0].clear());
                if l0.data().is_empty() {
                    self.deallocate_block(l1.data_mut().ptrs[i1].clear());
                } else {
                    l1.data_mut().ptrs[i1] = self.sync_block(l0)?;
                }
                if l1.data().is_empty() {
                    self.deallocate_block(l2.data_mut().ptrs[i2].clear());
                } else {
                    l2.data_mut().ptrs[i2] = self.sync_block(l1)?;
                }
                if l2.data().is_empty() {
                    self.deallocate_block(l3.data_mut().ptrs[i3].clear());
                } else {
                    l3.data_mut().ptrs[i3] = self.sync_block(l2)?;
                }
                if l3.data().is_empty() {
                    self.deallocate_block(node.data_mut().level4[i4].clear());
                } else {
                    node.data_mut().level4[i4] = self.sync_block(l3)?;
                }
            }
        }

        Ok(())
    }

    fn sync_node_block_ptr(
        &mut self,
        node: &mut TreeData<Node>,
        block_offset: u64,
        ptr: BlockPtr<BlockRaw>,
    ) -> Result<()> {
        unsafe {
            match NodeLevel::new(block_offset).ok_or(Error::new(ERANGE))? {
                NodeLevel::L0(i0) => {
                    node.data_mut().level0[i0] = ptr;
                }
                NodeLevel::L1(i1, i0) => {
                    let mut l0 = self.read_block_or_default(node.data().level1[i1])?;

                    l0.data_mut().ptrs[i0] = ptr;
                    node.data_mut().level1[i1] = self.sync_block(l0)?;
                }
                NodeLevel::L2(i2, i1, i0) => {
                    let mut l1 = self.read_block_or_default(node.data().level2[i2])?;
                    let mut l0 = self.read_block_or_default(l1.data().ptrs[i1])?;

                    l0.data_mut().ptrs[i0] = ptr;
                    l1.data_mut().ptrs[i1] = self.sync_block(l0)?;
                    node.data_mut().level2[i2] = self.sync_block(l1)?;
                }
                NodeLevel::L3(i3, i2, i1, i0) => {
                    let mut l2 = self.read_block_or_default(node.data().level3[i3])?;
                    let mut l1 = self.read_block_or_default(l2.data().ptrs[i2])?;
                    let mut l0 = self.read_block_or_default(l1.data().ptrs[i1])?;

                    l0.data_mut().ptrs[i0] = ptr;
                    l1.data_mut().ptrs[i1] = self.sync_block(l0)?;
                    l2.data_mut().ptrs[i2] = self.sync_block(l1)?;
                    node.data_mut().level3[i3] = self.sync_block(l2)?;
                }
                NodeLevel::L4(i4, i3, i2, i1, i0) => {
                    let mut l3 = self.read_block_or_default(node.data().level4[i4])?;
                    let mut l2 = self.read_block_or_default(l3.data().ptrs[i3])?;
                    let mut l1 = self.read_block_or_default(l2.data().ptrs[i2])?;
                    let mut l0 = self.read_block_or_default(l1.data().ptrs[i1])?;

                    l0.data_mut().ptrs[i0] = ptr;
                    l1.data_mut().ptrs[i1] = self.sync_block(l0)?;
                    l2.data_mut().ptrs[i2] = self.sync_block(l1)?;
                    l3.data_mut().ptrs[i3] = self.sync_block(l2)?;
                    node.data_mut().level4[i4] = self.sync_block(l3)?;
                }
            }
        }

        Ok(())
    }

    pub fn read_node_inner(
        &mut self,
        node: &TreeData<Node>,
        mut offset: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        let node_size = node.data().size();
        let mut i = 0;
        while i < buf.len() && offset < node_size {
            let block_ptr = self.node_block_ptr(&node, offset / BLOCK_SIZE)?;
            let block = self.read_block(block_ptr)?;

            let j = (offset % BLOCK_SIZE) as usize;
            let len = min(
                buf.len() - i,
                min(BLOCK_SIZE - j as u64, node_size - offset) as usize,
            );
            buf[i..i + len].copy_from_slice(&block.data()[j..j + len]);

            i += len;
            offset += len as u64;
        }
        Ok(i)
    }

    pub fn read_node(
        &mut self,
        node_ptr: TreePtr<Node>,
        offset: u64,
        buf: &mut [u8],
        atime: u64,
        atime_nsec: u32,
    ) -> Result<usize> {
        let mut node = self.read_tree(node_ptr)?;
        let mut node_changed = false;

        let i = self.read_node_inner(&node, offset, buf)?;
        if i > 0 {
            let node_atime = node.data().atime();
            if atime > node_atime.0 || (atime == node_atime.0 && atime_nsec > node_atime.1) {
                let is_old = atime - node_atime.0 > 3600; // Last read was more than a day ago
                if is_old {
                    node.data_mut().set_atime(atime, atime_nsec);
                    node_changed = true;
                }
            }
        }

        if node_changed {
            self.sync_tree(node)?;
        }

        Ok(i)
    }

    pub fn truncate_node_inner(&mut self, node: &mut TreeData<Node>, size: u64) -> Result<bool> {
        let old_size = node.data().size();

        // Size already matches, return
        if old_size == size {
            return Ok(false);
        }

        if old_size < size {
            // If size is smaller, write zeroes until the size matches
            let zeroes = [0; BLOCK_SIZE as usize];

            let mut offset = old_size;
            while offset < size {
                let start = offset % BLOCK_SIZE;
                let end = if offset / BLOCK_SIZE == size / BLOCK_SIZE {
                    size % BLOCK_SIZE
                } else {
                    BLOCK_SIZE
                };
                self.write_node_inner(node, &mut offset, &zeroes[start as usize..end as usize])?;
            }
            assert_eq!(offset, size);
        } else {
            // Deallocate blocks
            for block in ((size + BLOCK_SIZE - 1) / BLOCK_SIZE..old_size / BLOCK_SIZE).rev() {
                self.remove_node_block_ptr(node, block)?;
            }
        }

        // Update size
        node.data_mut().set_size(size);

        Ok(true)
    }

    pub fn truncate_node(
        &mut self,
        node_ptr: TreePtr<Node>,
        size: u64,
        mtime: u64,
        mtime_nsec: u32,
    ) -> Result<()> {
        let mut node = self.read_tree(node_ptr)?;
        if self.truncate_node_inner(&mut node, size)? {
            let node_mtime = node.data().mtime();
            if mtime > node_mtime.0 || (mtime == node_mtime.0 && mtime_nsec > node_mtime.1) {
                node.data_mut().set_mtime(mtime, mtime_nsec);
            }

            self.sync_tree(node)?;
        }

        Ok(())
    }

    pub fn write_node_inner(
        &mut self,
        node: &mut TreeData<Node>,
        offset: &mut u64,
        buf: &[u8],
    ) -> Result<bool> {
        let mut node_changed = false;

        let node_blocks = (node.data().size() + BLOCK_SIZE - 1) / BLOCK_SIZE;

        let mut i = 0;
        while i < buf.len() {
            let mut block_ptr = if node_blocks > (*offset / BLOCK_SIZE) {
                self.node_block_ptr(node, *offset / BLOCK_SIZE)?
            } else {
                BlockPtr::default()
            };
            let mut block = unsafe { self.read_block_or_default(block_ptr)? };

            let j = (*offset % BLOCK_SIZE) as usize;
            let len = min(buf.len() - i, BLOCK_SIZE as usize - j);
            if block_ptr.is_null() || buf[i..i + len] != block.data()[j..j + len] {
                unsafe {
                    let old_addr = block.swap_addr(self.allocate()?);

                    block.data_mut()[j..j + len].copy_from_slice(&buf[i..i + len]);
                    block_ptr = self.write_block(block)?;

                    if old_addr != 0 {
                        self.deallocate(old_addr);
                    }
                }

                self.sync_node_block_ptr(node, *offset / BLOCK_SIZE, block_ptr)?;
                node_changed = true;
            }

            i += len;
            *offset += len as u64;
        }

        if node.data().size() < *offset {
            node.data_mut().set_size(*offset);
            node_changed = true;
        }

        Ok(node_changed)
    }

    pub fn write_node(
        &mut self,
        node_ptr: TreePtr<Node>,
        mut offset: u64,
        buf: &[u8],
        mtime: u64,
        mtime_nsec: u32,
    ) -> Result<usize> {
        let mut node = self.read_tree(node_ptr)?;

        if self.write_node_inner(&mut node, &mut offset, buf)? {
            let node_mtime = node.data().mtime();
            if mtime > node_mtime.0 || (mtime == node_mtime.0 && mtime_nsec > node_mtime.1) {
                node.data_mut().set_mtime(mtime, mtime_nsec);
            }

            self.sync_tree(node)?;
        }

        Ok(buf.len())
    }
}
