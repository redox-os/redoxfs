use alloc::string::String;
use alloc::vec::Vec;
use core::{fmt, mem, ops, slice};
use endian_num::Le;
use syscall::error::{Error, Result, EEXIST, EIO};

use crate::{
    BlockLevel, BlockPtr, BlockRaw, BlockTrait, DirEntry, DirList, BLOCK_SIZE, RECORD_LEVEL,
};

pub const HTREE_IDX_ENTRIES: usize = BLOCK_SIZE as usize / mem::size_of::<HTreePtr<BlockRaw>>();
const HTREE_IDX_PADDING: usize =
    BLOCK_SIZE as usize - mem::size_of::<[HTreePtr<BlockRaw>; HTREE_IDX_ENTRIES]>();

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(C, packed)]
pub struct HTreeHash(Le<u32>);

impl HTreeHash {
    // Create a MAX constant populated iwth the maximum value of Le<u32> minus 1
    pub const MAX: HTreeHash = HTreeHash(Le(u32::MAX - 1));

    #[cfg(not(test))]
    pub fn from_name(name: &str) -> Self {
        let hash = seahash::hash(name.as_bytes()) as u32;
        // Don't allow the default hash value to be calculated for a real hash
        if hash == u32::MAX {
            return Self::MAX;
        }
        Self(hash.into())
    }

    #[cfg(test)]
    pub fn from_name(name: &str) -> Self {
        // Allow overriding the hashing function to something easily controled for testing.
        let hash = if let Some(pos) = name.rfind("__") {
            let number_str = &name[pos + 2..];
            number_str.parse::<u32>().unwrap()
        } else {
            seahash::hash(name.as_bytes()) as u32
        };

        // Don't allow the default hash value to be calculated for a real hash
        if hash == u32::MAX {
            return Self::MAX;
        }
        Self(hash.into())
    }

    /// Returns the maximum of two `HTreeHash` values, ignoring the default hash value.
    pub fn max_ignoring_default(&self, other: Self) -> Self {
        let default = HTreeHash::default();
        if *self == default {
            return other;
        }
        if other == default {
            return *self;
        }
        if *self > other {
            *self
        } else {
            other
        }
    }

    pub fn find_max(dir_list: &DirList) -> Option<HTreeHash> {
        let mut max_hash = HTreeHash::default();
        dir_list.for_each_entry(|_ptr_bytes, name_bytes| {
            let name = String::from_utf8_lossy(name_bytes);
            let hash = HTreeHash::from_name(name.as_ref());
            max_hash = max_hash.max_ignoring_default(hash);
        });

        if max_hash == HTreeHash::default() {
            None
        } else {
            Some(max_hash)
        }
    }
}

impl Default for HTreeHash {
    /// The default hash value is the maximum possible value to push it to the end of the list when sorting.
    fn default() -> Self {
        Self(u32::MAX.into())
    }
}

#[repr(C, packed)]
pub struct HTreePtr<T> {
    pub htree_hash: HTreeHash,
    pub ptr: BlockPtr<T>,
}

impl<T> HTreePtr<T> {
    pub fn new(htree_hash: HTreeHash, ptr: BlockPtr<T>) -> Self {
        Self { htree_hash, ptr }
    }

    /// Cast HTreePtr to another type
    ///
    /// # Safety
    /// Unsafe because it can be used to transmute types
    pub unsafe fn cast<U>(self) -> HTreePtr<U> {
        HTreePtr {
            htree_hash: self.htree_hash,
            ptr: self.ptr.cast(),
        }
    }
}

impl<T> HTreePtr<T> {
    pub fn is_null(&self) -> bool {
        self.ptr.is_null()
    }
}

impl<T> Clone for HTreePtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for HTreePtr<T> {}

impl<T> Default for HTreePtr<T> {
    fn default() -> Self {
        Self {
            htree_hash: HTreeHash::default(),
            ptr: BlockPtr::default(),
        }
    }
}

impl<T> fmt::Debug for HTreePtr<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let htree_hash = self.htree_hash;
        let ptr = self.ptr;
        f.debug_struct("BlockPtr")
            .field("htree_hash", &htree_hash)
            .field("ptr", &ptr)
            .finish()
    }
}

#[repr(C, packed)]
pub struct HTreeNode<T> {
    pub ptrs: [HTreePtr<T>; HTREE_IDX_ENTRIES],
    padding: [u8; HTREE_IDX_PADDING],
}

impl<T> HTreeNode<T> {
    pub fn find_max_htree_hash(&self) -> Option<HTreeHash> {
        let mut hash = HTreeHash::default();
        for entry in self.ptrs.iter() {
            hash = hash.max_ignoring_default(entry.htree_hash);
        }

        if hash != HTreeHash::default() {
            Some(hash)
        } else {
            None
        }
    }

    pub fn find_ptrs_for_read(
        &self,
        htree_hash: HTreeHash,
    ) -> impl Iterator<Item = (usize, &HTreePtr<T>)> {
        let mut last_hash = HTreeHash(0.into());
        self.ptrs
            .iter()
            .enumerate()
            .filter(move |(_idx, entry)| entry.htree_hash >= htree_hash)
            .take_while(move |(_idx, entry)| {
                let should_take = !entry.is_null() && last_hash <= htree_hash;
                last_hash = entry.htree_hash;
                should_take
            })
    }
}

unsafe impl<T> BlockTrait for HTreeNode<T> {
    fn empty(level: BlockLevel) -> Option<Self> {
        if level.0 <= RECORD_LEVEL {
            Some(Self {
                ptrs: [HTreePtr::default(); HTREE_IDX_ENTRIES],
                padding: [0; HTREE_IDX_PADDING],
            })
        } else {
            None
        }
    }
}

impl<T> ops::Deref for HTreeNode<T> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const HTreeNode<T> as *const u8,
                mem::size_of::<HTreeNode<T>>(),
            ) as &[u8]
        }
    }
}

impl<T> ops::DerefMut for HTreeNode<T> {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(
                self as *mut HTreeNode<T> as *mut u8,
                mem::size_of::<HTreeNode<T>>(),
            ) as &mut [u8]
        }
    }
}

pub fn add_inner_node<T>(
    parent: &mut HTreeNode<T>,
    new_ptr: HTreePtr<T>,
) -> Result<Option<(HTreeHash, HTreeNode<T>)>> {
    // Update the input htree parameters in place
    for ptr in parent.ptrs.iter_mut() {
        if ptr.is_null() {
            *ptr = new_ptr;
            parent.ptrs.sort_by(|a, b| a.htree_hash.cmp(&b.htree_hash));
            return Ok(None);
        }
    }

    // The parent is full. We need to split it into two by half, ordered by the htree hash.
    let mut all_ptrs = Vec::with_capacity(parent.ptrs.len() + 1);
    for ptr in parent.ptrs.iter() {
        all_ptrs.push(*ptr);
    }
    all_ptrs.push(new_ptr);
    all_ptrs.sort_by(|a, b| a.htree_hash.cmp(&b.htree_hash));
    let half_idx = all_ptrs.len() / 2;

    // Find if there are duplicate name hashes on the boundary of where we want to split
    let half_name_hash = all_ptrs[half_idx].htree_hash;
    let mut first_idx = half_idx;
    let mut last_idx = half_idx;
    for (i, ptr) in all_ptrs.iter().enumerate() {
        if ptr.htree_hash == half_name_hash {
            if i < first_idx {
                first_idx = i;
            }
            if i > last_idx {
                last_idx = i;
            }
        }
    }

    // Split the entries_with_name_hash list at the index that minimizes the number of entries in each list while keeping the duplicate name hashes together
    let split = if (half_idx - first_idx) < (last_idx - half_idx) {
        first_idx
    } else {
        last_idx
    };

    let (ptrs1, ptrs2) = all_ptrs.split_at(split);

    // Update the existing parent with the first half of the entries
    let mut htree_idx1 = HTreeNode::empty(BlockLevel::default()).ok_or(Error::new(EIO))?;
    htree_idx1.ptrs[..ptrs1.len()].copy_from_slice(ptrs1);
    let _ = mem::replace(parent, htree_idx1);

    // Return the second half as a new sibling parent
    let mut htree_idx2 = HTreeNode::empty(BlockLevel::default()).ok_or(Error::new(EIO))?;
    htree_idx2.ptrs[..ptrs2.len()].copy_from_slice(ptrs2);

    let htree_hash2 = ptrs2[ptrs2.len() - 1].htree_hash;
    Ok(Some((htree_hash2, htree_idx2)))
}

pub fn add_dir_entry(
    dir_list: &mut DirList,
    htree_hash: &mut HTreeHash,
    dirent: DirEntry,
) -> Result<Option<(HTreeHash, DirList)>> {
    if let Some(name) = dirent.name() {
        if dir_list.find_entry(name).is_some() {
            return Err(Error::new(EEXIST));
        }
    }

    // Update the input htree parameters in place
    let name = dirent.name().ok_or(Error::new(EIO))?;
    if dir_list.append(&dirent) {
        *htree_hash = HTreeHash::from_name(name).max_ignoring_default(*htree_hash);
        return Ok(None);
    }

    // The dir_list is full. We need to split it into two dir_lists by half, ordered by the name hash.
    let mut entries_with_name_hash = Vec::with_capacity(dir_list.entry_count() + 1);
    for entry in dir_list.entries() {
        entries_with_name_hash.push((
            HTreeHash::from_name(entry.name().ok_or(Error::new(EIO))?),
            entry,
        ));
    }
    entries_with_name_hash.push((HTreeHash::from_name(dirent.name().unwrap()), dirent));
    entries_with_name_hash.sort_by(|a, b| a.0.cmp(&b.0));
    let half = entries_with_name_hash.len() / 2;
    let half_name_hash = entries_with_name_hash[half].0;

    // Find if there are duplicate name hashes on the boundary of where we want to split
    let mut first_idx = half;
    let mut last_idx = half;
    for (i, (name_hash, _)) in entries_with_name_hash.iter().enumerate() {
        if *name_hash == half_name_hash {
            if i < first_idx {
                first_idx = i;
            }
            if i > last_idx {
                last_idx = i;
            }
        }
    }
    last_idx += 1;

    // Split the entries_with_name_hash list at the index that minimizes the number of entries in each list while keeping the duplicate name hashes together
    let split = if (half - first_idx) < (last_idx - half) {
        first_idx
    } else {
        last_idx
    };
    let split = split.max(1);

    let sorted_entries = entries_with_name_hash
        .iter()
        .map(|(_, entry)| *entry)
        .collect::<Vec<DirEntry>>();

    let (entries1, entries2) = sorted_entries.split_at(split);

    // Update the existing dir_list with the first half of the entries
    let mut new_dir_list = DirList::empty(BlockLevel::default()).ok_or(Error::new(EIO))?;
    for entry in entries1.iter() {
        new_dir_list.append(entry);
    }
    let _ = mem::replace(dir_list, new_dir_list);
    *htree_hash = entries_with_name_hash[entries1.len() - 1].0;

    // Return the second half of the entries as a new dir_list
    let mut new_dir_list = DirList::empty(BlockLevel::default()).ok_or(Error::new(EIO))?;
    for entry in entries2.iter() {
        new_dir_list.append(entry);
    }
    let new_name_hash = entries_with_name_hash[entries_with_name_hash.len() - 1].0;
    Ok(Some((new_name_hash, new_dir_list)))
}

//
// MARK: Unit Tests
//

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alloc::string::ToString;
    use crate::TreePtr;
    use alloc::format;
    use alloc::string::String;

    #[test]
    fn htree_ptr_size_test() {
        assert_eq!(mem::size_of::<HTreePtr<BlockRaw>>(), 20);
    }

    #[test]
    fn htree_node_size_test() {
        assert_eq!(mem::size_of::<HTreeNode<BlockRaw>>(), BLOCK_SIZE as usize);
    }

    #[test]
    fn htree_hash_max_test() {
        assert_eq!(HTreeHash::MAX, HTreeHash((u32::MAX - 1).into()));
    }

    #[test]
    fn htree_hash_max_ignoring_default_test() {
        let default = HTreeHash::default();
        let hash1 = HTreeHash(0.into());
        let hash2 = HTreeHash(1.into());

        assert_eq!(hash1.max_ignoring_default(default), hash1);
        assert_eq!(default.max_ignoring_default(hash1), hash1);
        assert_eq!(hash1.max_ignoring_default(hash2), hash2);
    }

    #[test]
    fn htree_node_find_max_htree_hash() {
        // In practice, the HTreeHash values should always be in sorted order
        let mut htree_node: HTreeNode<String> = HTreeNode::empty(BlockLevel::default()).unwrap();
        htree_node.ptrs[0] = HTreePtr::new(HTreeHash(0.into()), BlockPtr::marker(0));
        htree_node.ptrs[1] = HTreePtr::new(HTreeHash(1.into()), BlockPtr::marker(0));
        htree_node.ptrs[2] = HTreePtr::new(HTreeHash(2.into()), BlockPtr::marker(0));

        assert_eq!(
            htree_node.find_max_htree_hash().unwrap(),
            HTreeHash(2.into())
        );

        htree_node.ptrs[2] = HTreePtr::default();
        assert_eq!(
            htree_node.find_max_htree_hash().unwrap(),
            HTreeHash(1.into())
        );

        htree_node.ptrs[1] = HTreePtr::default();
        assert_eq!(
            htree_node.find_max_htree_hash().unwrap(),
            HTreeHash(0.into())
        );

        htree_node.ptrs[0] = HTreePtr::default();
        assert!(htree_node.find_max_htree_hash().is_none());

        // For thoroughness, test with HTreeHash out of order
        htree_node.ptrs[2] = HTreePtr::new(HTreeHash(4.into()), BlockPtr::marker(0));
        htree_node.ptrs[4] = HTreePtr::new(HTreeHash(6.into()), BlockPtr::marker(0));
        htree_node.ptrs[6] = HTreePtr::new(HTreeHash(2.into()), BlockPtr::marker(0));
        assert_eq!(
            htree_node.find_max_htree_hash().unwrap(),
            HTreeHash(6.into())
        );
    }

    #[test]
    fn htree_node_find_for_read() {
        let mut htree_node: HTreeNode<String> = HTreeNode::empty(BlockLevel::default()).unwrap();
        htree_node.ptrs[0] = HTreePtr::new(HTreeHash(0.into()), BlockPtr::marker(0));
        htree_node.ptrs[1] = HTreePtr::new(HTreeHash(1.into()), BlockPtr::marker(0));
        htree_node.ptrs[2] = HTreePtr::new(HTreeHash(2.into()), BlockPtr::marker(0));
        htree_node.ptrs[3] = HTreePtr::new(HTreeHash(2.into()), BlockPtr::marker(0));
        htree_node.ptrs[4] = HTreePtr::new(HTreeHash(3.into()), BlockPtr::marker(0));
        htree_node.ptrs[5] = HTreePtr::new(HTreeHash(3.into()), BlockPtr::marker(0));
        htree_node.ptrs[6] = HTreePtr::new(HTreeHash(5.into()), BlockPtr::marker(0));
        htree_node.ptrs[7] = HTreePtr::new(HTreeHash(6.into()), BlockPtr::marker(0));

        // Confirm that a hash that does not exist, but is less than an existing hash results in a single entry
        let mut iter = htree_node.find_ptrs_for_read(HTreeHash(4.into()));
        let mut val = iter.next().unwrap();
        assert_eq!(val.0, 6);
        assert_eq!(val.1.htree_hash, HTreeHash(5.into()));
        assert!(iter.next().is_none());

        // Confirm that a hash that equals an existing hash results in the match and one following entry
        let mut iter = htree_node.find_ptrs_for_read(HTreeHash(1.into()));
        val = iter.next().unwrap();
        assert_eq!(val.0, 1);
        assert_eq!(val.1.htree_hash, HTreeHash(1.into()));
        val = iter.next().unwrap();
        assert_eq!(val.0, 2);
        assert_eq!(val.1.htree_hash, HTreeHash(2.into()));
        assert!(iter.next().is_none());

        // Confirm that multiple exact hash matches are all returned plus the next entry
        let mut iter = htree_node.find_ptrs_for_read(HTreeHash(2.into()));
        val = iter.next().unwrap();
        assert_eq!(val.0, 2);
        assert_eq!(val.1.htree_hash, HTreeHash(2.into()));
        val = iter.next().unwrap();
        assert_eq!(val.0, 3);
        assert_eq!(val.1.htree_hash, HTreeHash(2.into()));
        val = iter.next().unwrap();
        assert_eq!(val.0, 4);
        assert_eq!(val.1.htree_hash, HTreeHash(3.into()));
        assert!(iter.next().is_none());

        // Confirm that if the last entry matches and the next entry is null, only the match is returned
        let mut iter = htree_node.find_ptrs_for_read(HTreeHash(6.into()));
        val = iter.next().unwrap();
        assert_eq!(val.0, 7);
        assert_eq!(val.1.htree_hash, HTreeHash(6.into()));
        assert!(iter.next().is_none());

        // Confirm that if a hash that is larger than any existing entries, then no entries are returned
        let mut iter = htree_node.find_ptrs_for_read(HTreeHash(7.into()));
        assert!(iter.next().is_none());
    }

    #[test]
    fn add_dir_entry_exists_test() {
        let mut dir_list = DirList::empty(BlockLevel::default()).unwrap();
        let mut htree_hash = HTreeHash::default();
        let dirent = DirEntry::new(TreePtr::new(123), "test");
        let new_sibling = add_dir_entry(&mut dir_list, &mut htree_hash, dirent).unwrap();
        assert!(new_sibling.is_none());
        assert_eq!(htree_hash, HTreeHash::from_name("test"));
        assert_eq!(dir_list.entries().next().unwrap().name(), Some("test"));

        // Add the same entry again, and it should fail with an appropriate IO error
        let dirent = DirEntry::new(TreePtr::new(123), "test");
        let error_expected = add_dir_entry(&mut dir_list, &mut htree_hash, dirent);
        assert!(error_expected.is_err());
        assert_eq!(error_expected.err().unwrap().errno, EEXIST);
    }

    #[test]
    fn add_dir_entry_many_test() {
        let mut dir_list = DirList::empty(BlockLevel::default()).unwrap();
        let mut htree_hash = HTreeHash::default();
        let total_count = 16;

        // Fill up the dir_list
        for i in 0..total_count {
            let v: usize = i % 10;
            let dirent = DirEntry::new(TreePtr::new(123), format!("test{v}_{i:0244}").as_str());
            let new_sibling = add_dir_entry(&mut dir_list, &mut htree_hash, dirent).unwrap();
            assert!(new_sibling.is_none());
        }

        // The maximum htree_hash should be retained
        let max_tree_hash =
            dir_list
                .entries()
                .enumerate()
                .fold(HTreeHash::default(), |max, (i, _)| {
                    let v = i % 10;
                    let hash = HTreeHash::from_name(format!("test{v}_{i:0244}").as_str());
                    max.max_ignoring_default(hash)
                });
        assert_eq!(htree_hash, max_tree_hash);

        // Confirm all the entries exist. Note they happen to be in insert order
        for (i, entry) in dir_list.entries().enumerate() {
            let v = i % 10;
            assert_eq!(entry.name(), Some(format!("test{v}_{i:0244}").as_str()));
        }

        // Test a split by adding one more entry
        let dirent = DirEntry::new(TreePtr::new(123), "test_split");
        let new_sibling = add_dir_entry(&mut dir_list, &mut htree_hash, dirent).unwrap();
        let (new_sibling_htree_hash, new_sibling_dir_list) =
            new_sibling.expect("new_sibling should be created");
        // assert!(new_sibling_dir_list.entries.len() );
        assert!(new_sibling_htree_hash > htree_hash);

        // The htree_hash should be less than the minimum htree_hash in new_sibling_dir_list
        let new_sibling_min_htree_hash = new_sibling_dir_list
            .entries()
            .filter(|entry| !entry.node_ptr().is_null())
            .fold(HTreeHash::default(), |min, entry| {
                let hash = HTreeHash::from_name(entry.name().unwrap());
                min.min(hash)
            });
        assert!(htree_hash < new_sibling_min_htree_hash);

        // Confirm all the entries exist across both dir_lists
        let mut expected_names: Vec<String> = (0..total_count)
            .map(|i| {
                let v = i % 10;
                format!("test{v}_{i:0244}")
            })
            .collect();
        expected_names.push("test_split".to_string());
        expected_names.sort();

        let mut dir_list_entry_count = 0;
        for entry in dir_list.entries() {
            dir_list_entry_count += 1;
            let name = entry.name().unwrap().to_string();
            let _ = expected_names.remove(expected_names.binary_search(&name).unwrap());
        }

        let mut new_sibling_entry_count = 0;
        for entry in new_sibling_dir_list.entries() {
            new_sibling_entry_count += 1;
            let name = entry.name().unwrap().to_string();
            let _ = expected_names.remove(expected_names.binary_search(&name).unwrap());
        }
        assert!(expected_names.is_empty());

        // Confirm that the split is in half
        assert!((dir_list_entry_count as i32 - new_sibling_entry_count).abs() <= 1);
    }

    #[test]
    fn add_inner_node_simple_test() {
        let mut htree_node: HTreeNode<_> = HTreeNode::empty(BlockLevel::default()).unwrap();
        let htree_ptr: HTreePtr<_> = HTreePtr::<BlockRaw> {
            htree_hash: HTreeHash::from_name("test"),
            ptr: BlockPtr::marker(0),
        };
        let new_sibling = add_inner_node(&mut htree_node, htree_ptr).unwrap();
        assert!(new_sibling.is_none());
        assert_eq!(htree_node.ptrs[0].htree_hash, HTreeHash::from_name("test"));
    }

    #[test]
    fn add_inner_node_multiple_test() {
        let mut htree_node: HTreeNode<_> = HTreeNode::empty(BlockLevel::default()).unwrap();

        for i in 0..HTREE_IDX_ENTRIES {
            let htree_ptr: HTreePtr<_> = HTreePtr::<BlockRaw> {
                htree_hash: HTreeHash(((100_000 + (i % 10) * 1000 + i) as u32).into()),
                ptr: BlockPtr::marker(0),
            };
            let new_sibling = add_inner_node(&mut htree_node, htree_ptr).unwrap();
            assert!(new_sibling.is_none());

            // Confirm that the htree_ptrs are in sorted order at the start of the ptrs list
            let mut prev_hash = HTreeHash::default();
            let mut count = 0;
            for ptr in htree_node.ptrs.iter() {
                if ptr.is_null() {
                    continue;
                }
                assert!(
                    ptr.htree_hash.max_ignoring_default(prev_hash) == ptr.htree_hash,
                    "index {i}: {:?} > {:?}",
                    ptr.htree_hash,
                    prev_hash
                );
                prev_hash = ptr.htree_hash;
                count += 1;
            }
            assert_eq!(count, i + 1);
        }

        // Confirm all expected hashes are present
        let mut expected_hashes: Vec<u32> = (0..HTREE_IDX_ENTRIES)
            .map(|i| (100_000 + (i % 10) * 1000 + i) as u32)
            .collect();
        expected_hashes.sort();

        for ptr in htree_node.ptrs.iter() {
            if ptr.is_null() {
                break;
            }
            let idx = expected_hashes
                .binary_search(&ptr.htree_hash.0.into())
                .unwrap();
            expected_hashes.remove(idx);
        }
        assert!(expected_hashes.is_empty());

        // Force a split by adding one more entry
        let htree_ptr: HTreePtr<_> = HTreePtr::<BlockRaw> {
            htree_hash: HTreeHash(130_000.into()),
            ptr: BlockPtr::marker(0),
        };

        let mut expected_hashes: Vec<u32> = (0..HTREE_IDX_ENTRIES)
            .map(|i| (100_000 + (i % 10) * 1000 + i) as u32)
            .collect();
        expected_hashes.push(130_000);
        expected_hashes.sort();

        let new_sibling = add_inner_node(&mut htree_node, htree_ptr).unwrap();
        let new_sibling = new_sibling.expect("new_sibling should be created");

        // Confirm all the entries exist across both htree_nodes
        let mut htree_node_entry_count = 0;
        for ptr in htree_node.ptrs.iter() {
            if ptr.ptr.is_null() {
                break;
            }
            htree_node_entry_count += 1;
            let idx = expected_hashes
                .binary_search(&ptr.htree_hash.0.into())
                .unwrap();
            expected_hashes.remove(idx);
        }

        let mut new_sibling_entry_count = 0;
        for ptr in new_sibling.1.ptrs.iter() {
            if ptr.ptr.is_null() {
                break;
            }
            new_sibling_entry_count += 1;
            let idx = expected_hashes
                .binary_search(&ptr.htree_hash.0.into())
                .unwrap();
            expected_hashes.remove(idx);
        }
        assert!(
            expected_hashes.is_empty(),
            "expected_hashes should be empty, but had length {}: {:?}",
            expected_hashes.len(),
            expected_hashes
        );

        // Confirm that the split is in half
        assert!((htree_node_entry_count as i32 - new_sibling_entry_count).abs() <= 1);
    }
}
