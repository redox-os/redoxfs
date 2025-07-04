use crate::htree::{HTreeHash, HTreeNode, HTreePtr, HTREE_IDX_ENTRIES};
use crate::{
    unmount_path, BlockAddr, BlockData, BlockLevel, BlockPtr, DirEntry, DirList, DiskMemory,
    DiskSparse, FileSystem, Node, TreePtr, ALLOC_GC_THRESHOLD, BLOCK_SIZE,
};
use core::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use std::thread::sleep;
use std::time::Duration;
use std::{fs, thread, time};

static IMAGE_SEQ: AtomicUsize = AtomicUsize::new(0);

fn with_redoxfs<T, F>(callback: F) -> T
where
    T: Send + Sync + 'static,
    F: FnOnce(FileSystem<DiskSparse>) -> T + Send + Sync + 'static,
{
    let disk_path = format!("image{}.bin", IMAGE_SEQ.fetch_add(1, Relaxed));

    let res = {
        let disk = DiskSparse::create(dbg!(&disk_path), 1024 * 1024 * 1024).unwrap();

        let ctime = dbg!(time::SystemTime::now().duration_since(time::UNIX_EPOCH)).unwrap();
        let fs = FileSystem::create(disk, None, ctime.as_secs(), ctime.subsec_nanos()).unwrap();

        callback(fs)
    };

    dbg!(fs::remove_file(dbg!(disk_path))).unwrap();

    res
}

fn with_mounted<T, F>(callback: F) -> T
where
    T: Send + Sync + 'static,
    F: FnOnce(&Path) -> T + Send + Sync + 'static,
{
    let mount_path_o = format!("image{}", IMAGE_SEQ.fetch_add(1, Relaxed));
    let mount_path = mount_path_o.clone();

    let res = with_redoxfs(move |fs| {
        if cfg!(not(target_os = "redox")) {
            if !Path::new(&mount_path).exists() {
                dbg!(fs::create_dir(dbg!(&mount_path))).unwrap();
            }
        }
        let join_handle = crate::mount(fs, dbg!(mount_path), move |real_path| {
            let real_path = real_path.to_owned();
            thread::spawn(move || {
                let res = catch_unwind(AssertUnwindSafe(|| callback(&real_path)));

                let real_path = real_path.to_str().unwrap();

                if cfg!(target_os = "redox") {
                    dbg!(fs::remove_file(dbg!(format!(":{}", real_path)))).unwrap();
                } else {
                    if !dbg!(Command::new("sync").status()).unwrap().success() {
                        panic!("sync failed");
                    }

                    if !unmount_path(real_path).is_ok() {
                        // There seems to be a race condition where the device can be busy when trying to unmount.
                        // So, we pause for a moment and retry. There will still be an error output to the logs
                        // for the first failed attempt.
                        sleep(Duration::from_millis(200));
                        if !unmount_path(real_path).is_ok() {
                            panic!("umount failed");
                        }
                    }
                }

                res.unwrap()
            })
        })
        .unwrap();

        join_handle.join().unwrap()
    });

    if cfg!(not(target_os = "redox")) {
        dbg!(fs::remove_dir(dbg!(mount_path_o))).unwrap();
    }

    res
}

#[test]
fn simple() {
    with_mounted(|path| {
        dbg!(fs::create_dir(&path.join("test"))).unwrap();
    })
}

#[test]
fn create_and_remove_file() {
    with_mounted(|path| {
        let file_name = "test_file.txt";
        let file_path = path.join(file_name);

        // Create the file
        fs::write(&file_path, "Hello, world!").unwrap();
        assert!(fs::exists(&file_path).unwrap());

        // Read the file
        let contents = fs::read_to_string(&file_path).unwrap();
        assert_eq!(contents, "Hello, world!");

        // Remove the file
        fs::remove_file(&file_path).unwrap();
        assert!(!fs::exists(&file_path).unwrap());
    });
}

#[test]
fn create_and_remove_directory() {
    with_mounted(|path| {
        let dir_name = "test_dir";
        let dir_path = path.join(dir_name);

        // Create the directory
        fs::create_dir(&dir_path).unwrap();
        assert!(fs::exists(&dir_path).unwrap());

        // Check that the directory is empty
        let entries: Vec<_> = fs::read_dir(&dir_path)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(entries.is_empty());

        // Add a file to the directory
        let file_name = "test_file.txt";
        let file_path = dir_path.join(file_name);
        fs::write(&file_path, "Hello, world!").unwrap();

        // Check that the dir cannot be removed when not empty
        let error = fs::remove_dir(&dir_path);
        assert!(error.is_err());
        assert_eq!(
            error.unwrap_err().kind(),
            std::io::ErrorKind::DirectoryNotEmpty
        );

        // Remove the file
        fs::remove_file(&file_path).unwrap();

        // Remove the directory
        fs::remove_dir(&dir_path).unwrap();
        assert!(!fs::exists(&dir_path).unwrap());
    });
}

#[test]
fn create_and_remove_symlink() {
    with_mounted(|path| {
        let real_file = "real_file.txt";
        let real_path = path.join(real_file);
        let symlink_file = "symlink_to_real_file.txt";
        let symlink_path = path.join(symlink_file);

        // Create the real file
        fs::write(&real_path, "Hello, world!").unwrap();

        // Create the symmlink according to the platform
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_file, &symlink_path).unwrap();

        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&real_file, &symlink_path).unwrap();

        // Check that the symlink exists and points to the correct target
        let exists = fs::exists(&symlink_path);
        assert!(
            exists.is_ok() && exists.unwrap(),
            "Symlink should exist but was: {:?}",
            fs::exists(&symlink_path)
        );
        let symlink_metadata = fs::symlink_metadata(&symlink_path).unwrap();
        assert!(symlink_metadata.file_type().is_symlink());
        let target = fs::read_link(&symlink_path).unwrap();
        assert_eq!(target.to_str().unwrap(), real_file);
        assert_eq!(fs::read(&symlink_path).unwrap(), b"Hello, world!");

        // Confirm the symlink cannot be removed as a directory
        let error = fs::remove_dir(&symlink_path);
        assert!(error.is_err());
        assert_eq!(error.unwrap_err().kind(), std::io::ErrorKind::NotADirectory);

        // Remove the symlink
        fs::remove_file(&symlink_path).unwrap();
        assert!(!fs::exists(&symlink_path).unwrap());
    });
}

#[cfg(target_os = "redox")]
#[test]
fn mmap() {
    use syscall;

    //TODO
    with_mounted(|path| {
        use std::slice;

        let path = dbg!(path.join("test"));

        let mmap_inner = |write: bool| {
            let fd = dbg!(libredox::call::open(
                path.to_str().unwrap(),
                libredox::flag::O_CREAT | libredox::flag::O_RDWR | libredox::flag::O_CLOEXEC,
                0,
            ))
            .unwrap();

            let map = unsafe {
                slice::from_raw_parts_mut(
                    dbg!(libredox::call::mmap(libredox::call::MmapArgs {
                        fd,
                        offset: 0,
                        length: 128,
                        prot: libredox::flag::PROT_READ | libredox::flag::PROT_WRITE,
                        flags: libredox::flag::MAP_SHARED,
                        addr: core::ptr::null_mut(),
                    }))
                    .unwrap() as *mut u8,
                    128,
                )
            };

            // Maps should be available after closing
            assert_eq!(dbg!(libredox::call::close(fd)), Ok(()));

            for i in 0..128 {
                if write {
                    map[i as usize] = i;
                }
                assert_eq!(map[i as usize], i);
            }

            //TODO: add msync
            unsafe {
                assert_eq!(
                    dbg!(libredox::call::munmap(map.as_mut_ptr().cast(), map.len())),
                    Ok(())
                );
            }
        };

        mmap_inner(true);
        mmap_inner(false);
    })
}

#[test]
fn many_create_remove_should_not_increase_size() {
    with_redoxfs(|mut fs| {
        let initially_free = fs.allocator().free();
        let tree_ptr = TreePtr::<Node>::root();
        let name = "test";

        // Iterate over 255 times to prove deleted files don't retain space within the node tree
        // Iterate to an ALLOC_GC_THRESHOLD boundary to ensure the allocator GC reclaims space
        let start = fs.header.generation.to_ne();
        let end = start + ALLOC_GC_THRESHOLD;
        let end = end - (end % ALLOC_GC_THRESHOLD) + 1 + ALLOC_GC_THRESHOLD;
        for i in start..end {
            let _ = fs
                .tx(|tx| {
                    tx.create_node(
                        tree_ptr,
                        &format!("{}{}", name, i),
                        Node::MODE_FILE | 0644,
                        1,
                        0,
                    )?;
                    tx.remove_node(tree_ptr, &format!("{}{}", name, i), Node::MODE_FILE)
                })
                .unwrap();
        }

        // Any value greater than 0 indicates a storage leak
        let diff = initially_free - fs.allocator().free();
        assert_eq!(diff, 0);
    });
}

#[test]
fn many_create_then_many_remove_should_not_increase_size() {
    with_redoxfs(|mut fs| {
        let tree_ptr = TreePtr::<Node>::root();
        let initially_free = fs.allocator().free();
        let initial_size = fs.tx(|tx| tx.read_tree(tree_ptr)).unwrap().data().size();

        let end = 3000;
        for i in 0..end {
            let _ = fs
                .tx(|tx| {
                    tx.create_node(
                        tree_ptr,
                        &format!("test{}", i),
                        Node::MODE_FILE | 0644,
                        1,
                        0,
                    )
                })
                .unwrap();
        }

        for i in 0..end {
            let result =
                fs.tx(|tx| tx.remove_node(tree_ptr, &format!("test{}", i), Node::MODE_FILE));
            if result.is_err() {
                println!("Failed to delete on iteration {i}");
            }
            result.unwrap();
        }

        let final_size = fs.tx(|tx| tx.read_tree(tree_ptr)).unwrap().data().size();
        assert_eq!(initial_size, final_size);

        // Any value greater than 0 indicates a storage leak
        let _ = fs.tx(|tx| tx.sync(true));
        let diff = initially_free - fs.allocator().free();
        assert_eq!(diff, 0);
    });
}

#[test]
fn empty_dir() {
    with_redoxfs(|mut fs| {
        let root_ptr = TreePtr::root();
        let empty_dir = fs
            .tx(|tx| tx.create_node(root_ptr, "my_dir", Node::MODE_DIR, 1, 0))
            .unwrap();

        // List
        let mut children = Vec::<DirEntry>::new();
        let _ = fs
            .tx(|tx| tx.child_nodes(empty_dir.ptr(), &mut children))
            .unwrap();
        assert_eq!(children.len(), 0);

        // Find
        let error = fs.tx(|tx| tx.find_node(empty_dir.ptr(), "does_not_exist"));
        assert!(error.is_err());
        assert_eq!(error.unwrap_err().errno, syscall::error::ENOENT);

        // Remove
        let error = fs.tx(|tx| tx.remove_node(empty_dir.ptr(), "does_not_exist", Node::MODE_FILE));
        assert!(error.is_err());
        assert_eq!(error.unwrap_err().errno, syscall::error::ENOENT);
    })
}

// TODO: When increasing the total_count to 8000, the Allocator's deallocate() function surfaces as "slow" according to flamegraph. This
// appears to be the result of bulk deleting in this test, but I would bet that any filesystem that has lived for a long time would
// start to see degraded performance due to this.
#[test]
fn many_create_write_list_find_read_delete() {
    let disk = DiskMemory::new(1024 * 1024 * 1024);
    let ctime = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .unwrap();
    let mut fs = FileSystem::create(disk, None, ctime.as_secs(), ctime.subsec_nanos()).unwrap();
    let tree_ptr = TreePtr::<Node>::root();
    let total_count = 3000;

    // Create a bunch of files
    for i in 0..total_count {
        let result = fs.tx(|tx| {
            tx.create_node(
                tree_ptr,
                &format!("file{i:05}"),
                Node::MODE_FILE | 0644,
                1,
                0,
            )
        });
        if result.is_err() {
            println!("Failure on create iteration {i}");
        }

        let file_node = result.unwrap();
        let result = fs.tx(|tx| {
            tx.write_node(
                file_node.ptr(),
                0,
                format!("Hello World! #{i}").as_bytes(),
                ctime.as_secs(),
                ctime.subsec_nanos(),
            )
        });
        if result.is_err() {
            println!("Failure on write iteration {i}");
        }
        assert!(result.unwrap() > 0)
    }

    // Confirm that they can be listed
    {
        let mut children = Vec::<DirEntry>::with_capacity(total_count);
        let _ = fs.tx(|tx| tx.child_nodes(tree_ptr, &mut children)).unwrap();
        assert_eq!(
            children.len(),
            total_count,
            "The list of children should match the number of files created."
        );
        let mut children: Vec<String> = children
            .iter()
            .map(|entry| entry.name().unwrap_or_default().to_string())
            .collect();
        children.sort();

        for i in 0..total_count {
            let expected = format!("file{i:05}");
            let idx = children.binary_search(&expected);
            assert!(idx.is_ok(), "Children did not contain '{}'", expected);
        }
    }

    // Find and read the files
    for i in 0..total_count {
        let result = fs.tx(|tx| tx.find_node(tree_ptr, &format!("file{i:05}")));
        if result.is_err() {
            println!("Failure on find node iteration {i}");
        }

        let file_node = result.unwrap();
        let offset = 0;
        let mut buf = [0_u8; 32];
        let result = fs.tx(|tx| {
            tx.read_node(
                file_node.ptr(),
                offset,
                &mut buf,
                ctime.as_secs(),
                ctime.subsec_nanos(),
            )
        });
        if result.is_err() {
            println!("Failure on read iteration {i}");
        }
        let size = result.unwrap();
        let body = std::str::from_utf8(&buf[..size]).unwrap();
        assert_eq!(body, format!("Hello World! #{i}"));
    }

    // Delete all the files
    for i in 0..total_count {
        let file_name = format!("file{i:05}");
        let result = fs.tx(|tx| tx.remove_node(tree_ptr, &file_name, Node::MODE_FILE));
        if result.is_err() {
            println!("Failure on delete iteration {i}");
            result.unwrap();
        }
        let result = fs.tx(|tx| tx.find_node(tree_ptr, &file_name));
        if !result.is_err() || result.err().unwrap().errno != syscall::error::ENOENT {
            println!("Failure on delete verification iteration {i}");
            assert!(false, "Deletion appears to ahve failred");
        }
    }
}

#[test]
fn many_write_read_delete_mounted() {
    with_mounted(|path| {
        let total_count = 500;

        for i in 0..total_count {
            fs::write(
                &path.join(format!("file{}", i)),
                format!("Hello, number {i}!"),
            )
            .unwrap();
        }

        // Confirm each of the created files can be found and read
        for i in 0..total_count {
            let contents = fs::read_to_string(&path.join(format!("file{}", i))).unwrap();
            assert_eq!(contents, format!("Hello, number {i}!"));
        }

        // Remove all the files
        for i in 0..total_count {
            let file_path = path.join(format!("file{i}"));
            assert!(fs::exists(&file_path).unwrap());
            fs::remove_file(&file_path).unwrap();
            assert!(!fs::exists(&file_path).unwrap());
        }
    });
}

//
// MARK: H-Tree tests
//
// Note that most of these tests use a test specific HTreeHash implementation that will simply parse the numeric
// value after two underscores in the name. So a name of `my_file__10` would have a HTreeHash value of 10. This
// allows for some explicit placement of test values into the H-tree.
//

/// Create an unnaturally narrow but deep H-tree structure for efficient testing of the internal
/// algorithms used to change the H-tree state.
fn create_minimal_l2_htree(
    child1_name: &str,
    mut fs: FileSystem<DiskSparse>,
) -> (FileSystem<DiskSparse>, TreePtr<Node>) {
    let parent_ptr = TreePtr::<Node>::root();
    let child_ptr = fs
        .tx(|tx| {
            let mut parent = tx.read_tree(parent_ptr).unwrap();

            let child1_block_data = BlockData::new(
                unsafe { tx.allocate(BlockLevel::default()) }.unwrap(),
                Node::new(
                    Node::MODE_FILE,
                    parent.data().uid(),
                    parent.data().gid(),
                    1,
                    0,
                ),
            );
            let child1_block_ptr = unsafe { tx.write_block(child1_block_data) }.unwrap();
            let child1_ptr = tx.insert_tree(child1_block_ptr).unwrap();
            let child1_dir_entry = DirEntry::new(child1_ptr, child1_name);
            let child1_htree_hash = HTreeHash::from_name(child1_name);

            let mut dir_list = BlockData::<DirList>::empty(BlockAddr::default()).unwrap();
            dir_list.data_mut().append(&child1_dir_entry);
            let dir_ptr = tx.sync_block(dir_list).unwrap();

            let mut l1 = BlockData::<HTreeNode<DirList>>::empty(BlockAddr::default()).unwrap();
            l1.data_mut().ptrs[0] = HTreePtr::new(child1_htree_hash, dir_ptr);
            let l1_ptr = tx.sync_block(l1).unwrap();

            let mut l2 =
                BlockData::<HTreeNode<HTreeNode<DirList>>>::empty(BlockAddr::default()).unwrap();
            l2.data_mut().ptrs[0] = HTreePtr::new(child1_htree_hash, l1_ptr);
            let l2_ptr = tx.sync_block(l2).unwrap();
            let l2_ptr = unsafe { l2_ptr.cast() };

            parent.data_mut().level0[0] = BlockPtr::marker(2);
            parent.data_mut().level0[1] = l2_ptr;
            let size = parent.data().size() + BLOCK_SIZE * 4;
            parent.data_mut().size = size.into();
            tx.sync_tree(parent).unwrap();
            Ok(child1_ptr)
        })
        .unwrap();
    (fs, child_ptr)
}

#[test]
fn insert_dir_entry_without_hash_change() {
    with_redoxfs(|fs| {
        let parent_ptr = TreePtr::<Node>::root();

        // GIVEN a directory with H-Tree populated to level 2 and a new entry that lands
        // in the last existing DirList, but the hash sorts lower than the max hash in the DirList
        let child1_name = "child1__9";
        let child2_name = "child2__1";
        let child1_htree_hash = HTreeHash::from_name(child1_name);
        let (mut fs, child1_ptr) = create_minimal_l2_htree(child1_name, fs);

        let _ = fs.tx(|tx| {
            // WHEN the new child node is added to the parent directory
            let child2_node = tx
                .create_node(parent_ptr, child2_name, Node::MODE_FILE, 2, 0)
                .unwrap();

            // THEN the child node is added, but the H-Tree retains its structure, and the updated nodes retain
            // the old HTreeHash value
            let parent = tx.read_tree(parent_ptr).unwrap();
            assert!(parent.data().level0[0].is_marker());
            assert_eq!(parent.data().level0[0].addr().level().0, 2);

            let l2_ptr = unsafe { parent.data().level0[1].cast() };
            let l2: BlockData<HTreeNode<HTreeNode<DirList>>> = tx.read_block(l2_ptr).unwrap();

            let l1_ptr = l2.data().ptrs[0];
            let l1 = tx.read_block(l1_ptr.ptr).unwrap();
            assert_eq!(l1_ptr.htree_hash, child1_htree_hash);

            let dir_list_ptr = l1.data().ptrs[0];
            let dir_list = tx.read_block(dir_list_ptr.ptr).unwrap();
            assert_eq!(dir_list_ptr.htree_hash, child1_htree_hash);

            let mut entries: Vec<String> = dir_list
                .data()
                .entries()
                .map(|e| e.name().unwrap().to_string())
                .collect();
            entries.sort();

            assert_eq!(entries.len(), 2);
            assert_eq!(entries, vec![child1_name, child2_name]);

            // Validate listing child_nodes works
            let mut children = Vec::new();
            tx.child_nodes(parent_ptr, &mut children).unwrap();
            let mut children: Vec<&str> = children.iter().map(|e| e.name().unwrap()).collect();
            children.sort();
            assert_eq!(children, entries);

            // Validate find_node works
            assert_eq!(
                tx.find_node(parent_ptr, child1_name).unwrap().ptr().id(),
                child1_ptr.id()
            );
            assert_eq!(
                tx.find_node(parent_ptr, child2_name).unwrap().ptr().id(),
                child2_node.ptr().id()
            );

            // WHEN the new child node is removed from the parent directory
            tx.remove_node(parent_ptr, child2_name, Node::MODE_FILE)
                .unwrap();

            // THEN the child node is removed, the H-Tree retains its structure, and the updated nodes retain
            // the old HTreeHash value
            let parent = tx.read_tree(parent_ptr).unwrap();
            assert!(parent.data().level0[0].is_marker());
            assert_eq!(parent.data().level0[0].addr().level().0, 2);

            let l2_ptr = unsafe { parent.data().level0[1].cast() };
            let l2: BlockData<HTreeNode<HTreeNode<DirList>>> = tx.read_block(l2_ptr).unwrap();

            let l1_ptr = l2.data().ptrs[0];
            let l1 = tx.read_block(l1_ptr.ptr).unwrap();
            assert_eq!(l1_ptr.htree_hash, child1_htree_hash);

            let dir_list_ptr = l1.data().ptrs[0];
            let dir_list = tx.read_block(dir_list_ptr.ptr).unwrap();
            assert_eq!(dir_list_ptr.htree_hash, child1_htree_hash);

            let entries: Vec<String> = dir_list
                .data()
                .entries()
                .map(|e| e.name().unwrap().to_string())
                .collect();

            assert_eq!(entries.len(), 1);
            assert_eq!(entries, vec![child1_name]);

            // Validate listing child_nodes works
            let mut children = Vec::new();
            tx.child_nodes(parent_ptr, &mut children).unwrap();
            let children: Vec<&str> = children.iter().map(|e| e.name().unwrap()).collect();
            assert_eq!(children, entries);

            // Validate find_node works
            assert_eq!(
                tx.find_node(parent_ptr, child1_name).unwrap().ptr().id(),
                child1_ptr.id()
            );
            assert_eq!(
                tx.find_node(parent_ptr, child2_name).unwrap_err().errno,
                syscall::error::ENOENT
            );
            Ok(())
        });
    });
}

#[test]
fn insert_dir_entry_with_hash_change() {
    with_redoxfs(|fs| {
        let parent_ptr = TreePtr::<Node>::root();

        // GIVEN a directory with H-Tree populated to level 2 and a new entry that lands
        // in the last existing DirList, and the hash is sorted after the max hash in the DirList
        let child1_name = "child1__1";
        let child2_name = "child2__9";
        let (mut fs, child1_ptr) = create_minimal_l2_htree(child1_name, fs);

        let _ = fs.tx(|tx| {
            // WHEN the new child node is added to the parent directory
            let child2_node = tx
                .create_node(parent_ptr, child2_name, Node::MODE_FILE, 2, 0)
                .unwrap();

            // THEN the child node is added, the H-Tree retains its structure, and the updated nodes adopt
            // the new HTreeHash value
            let child2_htree_hash = HTreeHash::from_name(child2_name);
            let parent = tx.read_tree(parent_ptr).unwrap();
            assert!(parent.data().level0[0].is_marker());
            assert_eq!(parent.data().level0[0].addr().level().0, 2);

            let l2_ptr = unsafe { parent.data().level0[1].cast() };
            let l2: BlockData<HTreeNode<HTreeNode<DirList>>> = tx.read_block(l2_ptr).unwrap();

            let l1_ptr = l2.data().ptrs[0];
            let l1 = tx.read_block(l1_ptr.ptr).unwrap();
            assert_eq!(l1_ptr.htree_hash, child2_htree_hash);

            let dir_list_ptr = l1.data().ptrs[0];
            let dir_list = tx.read_block(dir_list_ptr.ptr).unwrap();
            assert_eq!(dir_list_ptr.htree_hash, child2_htree_hash);

            let mut entries: Vec<String> = dir_list
                .data()
                .entries()
                .map(|e| e.name().unwrap().to_string())
                .collect();
            entries.sort();

            assert_eq!(entries.len(), 2);
            assert_eq!(entries, vec![child1_name, child2_name]);

            // Validate listing child_nodes works
            let mut children = Vec::new();
            tx.child_nodes(parent_ptr, &mut children).unwrap();
            let mut children: Vec<&str> = children.iter().map(|e| e.name().unwrap()).collect();
            children.sort();
            assert_eq!(children, entries);

            // Validate find_node works
            assert_eq!(
                tx.find_node(parent_ptr, child1_name).unwrap().ptr().id(),
                child1_ptr.id()
            );
            assert_eq!(
                tx.find_node(parent_ptr, child2_name).unwrap().ptr().id(),
                child2_node.ptr().id()
            );

            // WHEN the new child node is removed from the parent directory
            tx.remove_node(parent_ptr, child2_name, Node::MODE_FILE)
                .unwrap();

            // THEN the child node is removed, the H-Tree retains its structure, and the updated nodes revert
            // to child1's HTreeHash value
            let child1_htree_hash = HTreeHash::from_name(child1_name);
            let parent = tx.read_tree(parent_ptr).unwrap();
            assert!(parent.data().level0[0].is_marker());
            assert_eq!(parent.data().level0[0].addr().level().0, 2);

            let l2_ptr = unsafe { parent.data().level0[1].cast() };
            let l2: BlockData<HTreeNode<HTreeNode<DirList>>> = tx.read_block(l2_ptr).unwrap();

            let l1_ptr = l2.data().ptrs[0];
            let l1 = tx.read_block(l1_ptr.ptr).unwrap();
            assert_eq!(l1_ptr.htree_hash, child1_htree_hash);

            let dir_list_ptr = l1.data().ptrs[0];
            let dir_list = tx.read_block(dir_list_ptr.ptr).unwrap();
            assert_eq!(dir_list_ptr.htree_hash, child1_htree_hash);

            let entries: Vec<String> = dir_list
                .data()
                .entries()
                .map(|e| e.name().unwrap().to_string())
                .collect();

            assert_eq!(entries.len(), 1);
            assert_eq!(entries, vec![child1_name]);

            // Validate listing child_nodes works
            let mut children = Vec::new();
            tx.child_nodes(parent_ptr, &mut children).unwrap();
            let children: Vec<&str> = children.iter().map(|e| e.name().unwrap()).collect();
            assert_eq!(children, entries);

            // Validate find_node works
            assert_eq!(
                tx.find_node(parent_ptr, child1_name).unwrap().ptr().id(),
                child1_ptr.id()
            );
            assert_eq!(
                tx.find_node(parent_ptr, child2_name).unwrap_err().errno,
                syscall::error::ENOENT
            );
            Ok(())
        });
    });
}

#[test]
fn delete_to_empty() {
    with_redoxfs(|fs| {
        let parent_ptr = TreePtr::<Node>::root();

        // GIVEN a nearly empty tree
        let child_name = "child1__9";
        let (mut fs, _child_ptr) = create_minimal_l2_htree(child_name, fs);

        // WHEN the last directory entry is removed
        fs.tx(|tx| tx.remove_node(parent_ptr, child_name, Node::MODE_FILE))
            .unwrap();

        // THEN the directory entry is removed, as are all the H-tree nodes
        fs.tx(|tx| {
            assert_eq!(
                tx.find_node(parent_ptr, child_name).unwrap_err().errno,
                syscall::error::ENOENT
            );

            let parent = tx.read_tree(parent_ptr).unwrap();
            assert!(!parent.data().level0[0].is_marker());
            assert!(parent.data().level0[0].addr().is_null());

            Ok(())
        })
        .unwrap();
    });
}

#[test]
fn split_htree_level0_to_level1() {
    with_redoxfs(|mut fs| {
        let parent_ptr = TreePtr::<Node>::root();

        // GIVEN a full root DirList
        fs.tx(|tx| {
            for i in 0..16 {
                let child_name = format!("child__{i:0243}");
                tx.create_node(parent_ptr, child_name.as_str(), Node::MODE_FILE, 1, 0)
                    .unwrap();
            }

            // Confirm preconditions: the level 0 is full of the expected entries.
            let parent = tx.read_tree(parent_ptr).unwrap();
            assert!(parent.data().level0[0].is_marker());
            assert_eq!(parent.data().level0[0].addr().level().0, 0);
            assert!(!parent.data().level0[0].addr().is_null());

            let dir_ptr: BlockPtr<DirList> = unsafe { parent.data().level0[1].cast() };
            let dir_list = tx.read_block(dir_ptr).unwrap();
            for (i, entry) in dir_list.data().entries().enumerate() {
                assert_eq!(entry.name().unwrap(), format!("child__{i:0243}"));
            }

            Ok(())
        })
        .unwrap();

        // WHEN one more entry is added
        fs.tx(|tx| {
            tx.create_node(
                parent_ptr,
                format!("child__{:0243}", 16).as_str(),
                Node::MODE_FILE,
                1,
                0,
            )
        })
        .unwrap();

        // THEN the level is increased and the DirList is split
        fs.tx(|tx| {
            let parent = tx.read_tree(parent_ptr).unwrap();
            assert!(parent.data().level0[0].is_marker());
            assert_eq!(parent.data().level0[0].addr().level().0, 1);
            assert!(!parent.data().level0[1].addr().is_null());

            let htree_ptr: BlockPtr<HTreeNode<DirList>> = unsafe { parent.data().level0[1].cast() };
            let htree_node = tx.read_block(htree_ptr).unwrap();
            assert!(!htree_node.data().ptrs[0].is_null());
            assert_eq!(
                htree_node.data().ptrs[0].htree_hash,
                HTreeHash::from_name(format!("child__{:0243}", 7).as_str())
            );
            assert!(!htree_node.data().ptrs[1].is_null());
            assert_eq!(
                htree_node.data().ptrs[1].htree_hash,
                HTreeHash::from_name(format!("child__{:0243}", 16).as_str())
            );

            assert!(htree_node.data().ptrs[2].is_null());

            let dir_list1 = tx.read_block(htree_node.data().ptrs[0].ptr).unwrap();
            let dir_list2 = tx.read_block(htree_node.data().ptrs[1].ptr).unwrap();

            assert_eq!(dir_list1.data().entry_count(), 8);
            assert_eq!(dir_list2.data().entry_count(), 9);

            for (i, entry) in dir_list1.data().entries().enumerate() {
                assert_eq!(entry.name().unwrap(), format!("child__{i:0243}"));
            }

            for (i, entry) in dir_list2.data().entries().enumerate() {
                let i = i + dir_list1.data().entry_count();
                assert_eq!(entry.name().unwrap(), format!("child__{i:0243}"));
            }

            Ok(())
        })
        .unwrap();

        // WHEN all entries in the first split are removed
        fs.tx(|tx| {
            for i in 0..8 {
                tx.remove_node(
                    parent_ptr,
                    format!("child__{i:0243}").as_str(),
                    Node::MODE_FILE,
                )
                .unwrap();
            }
            Ok(())
        })
        .unwrap();

        // THEN only the other split remains
        fs.tx(|tx| {
            let parent = tx.read_tree(parent_ptr).unwrap();
            assert!(parent.data().level0[0].is_marker());
            assert_eq!(parent.data().level0[0].addr().level().0, 1);
            assert!(!parent.data().level0[1].addr().is_null());

            let htree_ptr: BlockPtr<HTreeNode<DirList>> = unsafe { parent.data().level0[1].cast() };
            let htree_node = tx.read_block(htree_ptr).unwrap();
            assert!(!htree_node.data().ptrs[0].is_null());
            assert_eq!(
                htree_node.data().ptrs[0].htree_hash,
                HTreeHash::from_name(format!("child__{:0243}", 16).as_str())
            );
            assert!(htree_node.data().ptrs[1].is_null());

            Ok(())
        })
        .unwrap();

        // WHEN all entries in the second split are removed
        fs.tx(|tx| {
            for i in 8..17 {
                let name = format!("child__{i:0243}");
                let result = tx.remove_node(parent_ptr, name.as_str(), Node::MODE_FILE);
                if result.is_err() {
                    assert!(
                        false,
                        "Failed to remove file {name} with hash {:?} error {:?}",
                        HTreeHash::from_name(&name),
                        result.err()
                    );
                }
            }
            Ok(())
        })
        .unwrap();

        // THEN the level1 is collapsed back to an empty state
        fs.tx(|tx| {
            let parent = tx.read_tree(parent_ptr).unwrap();
            assert!(!parent.data().level0[0].is_marker());
            assert!(parent.data().level0[1].is_null());
            Ok(())
        })
        .unwrap();
    });
}

#[test]
fn split_htree_with_multiple_levels() {
    with_redoxfs(|fs| {
        let parent_ptr = TreePtr::<Node>::root();
        let (mut fs, _) = create_minimal_l2_htree(format!("child__{:0243}", 1000).as_str(), fs);

        // GIVEN a full root leaf node (DirList) with a full H-tree branch
        fs.tx(|tx| {
            for i in 1..16 {
                let i = i + 1000;
                let child_name = format!("child__{i:0243}");
                tx.create_node(parent_ptr, child_name.as_str(), Node::MODE_FILE, 1, 0)
                    .unwrap();
            }

            // Confirm preconditions: the level 0 is full of the expected entries.
            let mut parent = tx.read_tree(parent_ptr).unwrap();
            assert!(parent.data().level0[0].is_marker());
            assert_eq!(parent.data().level0[0].addr().level().0, 2);

            let l2_ptr: BlockPtr<HTreeNode<HTreeNode<DirList>>> =
                unsafe { parent.data().level0[1].cast() };
            let mut l2_node = tx.read_block(l2_ptr).unwrap();
            for i in 0..HTREE_IDX_ENTRIES {
                if i == 0 {
                    assert!(!l2_node.data().ptrs[i].is_null());
                } else {
                    assert!(l2_node.data().ptrs[i].is_null());
                    l2_node.data_mut().ptrs[i] = HTreePtr::new(HTreeHash::MAX, BlockPtr::marker(15))
                }
            }

            let l1_ptr = l2_node.data().ptrs[0];
            let mut l1_node = tx.read_block(l1_ptr.ptr).unwrap();
            for i in 0..HTREE_IDX_ENTRIES {
                if i == 0 {
                    assert!(!l1_node.data().ptrs[i].is_null());
                } else {
                    assert!(l1_node.data().ptrs[i].is_null());
                    l1_node.data_mut().ptrs[i] = HTreePtr::new(HTreeHash::MAX, BlockPtr::marker(15))
                }
            }

            l2_node.data_mut().ptrs[0].ptr = unsafe { tx.write_block(l1_node) }.unwrap();
            let l2_record_ptr = unsafe { tx.write_block(l2_node) }.unwrap();
            parent.data_mut().level0[1] = unsafe { l2_record_ptr.cast() };
            tx.sync_tree(parent).unwrap();

            Ok(())
        })
        .unwrap();

        // WHEN another entry is added to the full DirList
        fs.tx(|tx| {
            tx.create_node(
                parent_ptr,
                format!("child__{:0243}", 1).as_str(),
                Node::MODE_FILE,
                1,
                0,
            )
        })
        .unwrap();

        // THEN the branch splits all the way to the root, increasing the level
        fs.tx(|tx| {
            let parent = tx.read_tree(parent_ptr).unwrap();
            assert!(parent.data().level0[0].is_marker());
            assert_eq!(parent.data().level0[0].addr().level().0, 3);
            assert!(!parent.data().level0[1].addr().is_null());

            let htree_ptr: BlockPtr<HTreeNode<HTreeNode<HTreeNode<DirList>>>> =
                unsafe { parent.data().level0[1].cast() };
            let htree_node = tx.read_block(htree_ptr).unwrap();

            // Note that while a split tries to evenly divide the H-tree entries between the new two sibling nodes,
            // it tries to keep hash collisions together. This unnatural test scenario has a ton of the same max
            // value hash, so those get grouped together, and all our varying named entries end up in the other.
            assert!(!htree_node.data().ptrs[0].is_null());
            assert_eq!(
                htree_node.data().ptrs[0].htree_hash,
                HTreeHash::from_name(format!("child__{:0243}", 1015).as_str())
            );
            assert!(!htree_node.data().ptrs[1].is_null());
            assert_eq!(htree_node.data().ptrs[1].htree_hash, HTreeHash::MAX);
            assert!(htree_node.data().ptrs[2].is_null());

            let l3_node = tx.read_block(htree_node.data().ptrs[0].ptr).unwrap();
            let l2_node = tx.read_block(l3_node.data().ptrs[0].ptr).unwrap();
            assert_eq!(
                l2_node.data().ptrs[0].htree_hash,
                HTreeHash::from_name(format!("child__{:0243}", 1006).as_str())
            );
            assert_eq!(
                l2_node.data().ptrs[1].htree_hash,
                HTreeHash::from_name(format!("child__{:0243}", 1015).as_str())
            );
            assert!(l2_node.data().ptrs[2].is_null());

            Ok(())
        })
        .unwrap();

        // WHEN the max HTreeHash is removed from the smaller sibling
        fs.tx(|tx| {
            tx.remove_node(
                parent_ptr,
                format!("child__{:0243}", 1015).as_str(),
                Node::MODE_FILE,
            )
        })
        .unwrap();

        // THEN the HTreeHash values for that branch are updated
        fs.tx(|tx| {
            let parent = tx.read_tree(parent_ptr).unwrap();
            let htree_ptr: BlockPtr<HTreeNode<HTreeNode<HTreeNode<DirList>>>> =
                unsafe { parent.data().level0[1].cast() };
            let htree_node = tx.read_block(htree_ptr).unwrap();

            assert!(!htree_node.data().ptrs[0].is_null());
            assert_eq!(
                htree_node.data().ptrs[0].htree_hash,
                HTreeHash::from_name(format!("child__{:0243}", 1014).as_str())
            );
            assert!(!htree_node.data().ptrs[1].is_null());
            assert_eq!(htree_node.data().ptrs[1].htree_hash, HTreeHash::MAX);
            assert!(htree_node.data().ptrs[2].is_null());

            let l3_node = tx.read_block(htree_node.data().ptrs[0].ptr).unwrap();
            let l2_node = tx.read_block(l3_node.data().ptrs[0].ptr).unwrap();
            assert_eq!(
                l2_node.data().ptrs[0].htree_hash,
                HTreeHash::from_name(format!("child__{:0243}", 1006).as_str())
            );
            assert_eq!(
                l2_node.data().ptrs[1].htree_hash,
                HTreeHash::from_name(format!("child__{:0243}", 1014).as_str())
            );
            assert!(l2_node.data().ptrs[2].is_null());

            Ok(())
        })
        .unwrap();

        // WHEN removing all of one DirList
        fs.tx(|tx| {
            for i in 7..15 {
                let x = 1000 + i;
                tx.remove_node(
                    parent_ptr,
                    format!("child__{x:0243}").as_str(),
                    Node::MODE_FILE,
                )
                .unwrap();
            }
            Ok(())
        })
        .unwrap();

        // THEN that HTreeNode is returned to empty
        fs.tx(|tx| {
            let parent = tx.read_tree(parent_ptr).unwrap();
            let htree_ptr: BlockPtr<HTreeNode<HTreeNode<HTreeNode<DirList>>>> =
                unsafe { parent.data().level0[1].cast() };
            let htree_node = tx.read_block(htree_ptr).unwrap();

            assert!(!htree_node.data().ptrs[0].is_null());
            assert_eq!(
                htree_node.data().ptrs[0].htree_hash,
                HTreeHash::from_name(format!("child__{:0243}", 1006).as_str())
            );
            assert!(!htree_node.data().ptrs[1].is_null());
            assert_eq!(htree_node.data().ptrs[1].htree_hash, HTreeHash::MAX);
            assert!(htree_node.data().ptrs[2].is_null());

            let l3_node = tx.read_block(htree_node.data().ptrs[0].ptr).unwrap();
            let l2_node = tx.read_block(l3_node.data().ptrs[0].ptr).unwrap();
            assert_eq!(
                l2_node.data().ptrs[0].htree_hash,
                HTreeHash::from_name(format!("child__{:0243}", 1006).as_str())
            );
            assert!(l2_node.data().ptrs[1].is_null());
            assert!(l2_node.data().ptrs[2].is_null());

            Ok(())
        })
        .unwrap();

        // WHEN removing the other small DirList
        fs.tx(|tx| {
            tx.remove_node(
                parent_ptr,
                format!("child__{:0243}", 1).as_str(),
                Node::MODE_FILE,
            )
            .unwrap();
            for i in 0..7 {
                let x = 1000 + i;
                tx.remove_node(
                    parent_ptr,
                    format!("child__{x:0243}").as_str(),
                    Node::MODE_FILE,
                )
                .unwrap();
            }
            Ok(())
        })
        .unwrap();

        // THEN that HTreeNode is returned to empty
        fs.tx(|tx| {
            let parent = tx.read_tree(parent_ptr).unwrap();
            let htree_ptr: BlockPtr<HTreeNode<HTreeNode<HTreeNode<DirList>>>> =
                unsafe { parent.data().level0[1].cast() };
            let htree_node = tx.read_block(htree_ptr).unwrap();

            assert!(!htree_node.data().ptrs[0].is_null());
            assert_eq!(htree_node.data().ptrs[0].htree_hash, HTreeHash::MAX);
            assert!(htree_node.data().ptrs[1].is_null());

            Ok(())
        })
        .unwrap();
    });
}

/// Test a pathalogical case of many HTreeHash collisions. This should never happen in reality,
/// but the system can support it.
#[test]
fn split_htree_with_multiple_levels_using_duplicates() {
    with_redoxfs(|fs| {
        let parent_ptr = TreePtr::<Node>::root();
        let (mut fs, _) = create_minimal_l2_htree(format!("child{:0242}__0", 0).as_str(), fs);

        // GIVEN a full root leaf node (DirList) with a full H-tree branch
        fs.tx(|tx| {
            for i in 1..16 {
                let child_name = format!("child{i:0242}__0");
                tx.create_node(parent_ptr, child_name.as_str(), Node::MODE_FILE, 1, 0)
                    .unwrap();
            }

            // Confirm preconditions: the level 0 is full of the expected entries.
            let mut parent = tx.read_tree(parent_ptr).unwrap();
            assert!(parent.data().level0[0].is_marker());
            assert_eq!(parent.data().level0[0].addr().level().0, 2);

            let l2_ptr: BlockPtr<HTreeNode<HTreeNode<DirList>>> =
                unsafe { parent.data().level0[1].cast() };
            let mut l2_node = tx.read_block(l2_ptr).unwrap();
            for i in 0..HTREE_IDX_ENTRIES {
                if i == 0 {
                    assert!(!l2_node.data().ptrs[i].is_null());
                } else {
                    assert!(l2_node.data().ptrs[i].is_null());
                    l2_node.data_mut().ptrs[i] = HTreePtr::new(HTreeHash::MAX, BlockPtr::marker(15))
                }
            }

            let l1_ptr = l2_node.data().ptrs[0];
            let mut l1_node = tx.read_block(l1_ptr.ptr).unwrap();
            for i in 0..HTREE_IDX_ENTRIES {
                if i == 0 {
                    assert!(!l1_node.data().ptrs[i].is_null());
                } else {
                    assert!(l1_node.data().ptrs[i].is_null());
                    l1_node.data_mut().ptrs[i] = HTreePtr::new(HTreeHash::MAX, BlockPtr::marker(15))
                }
            }

            l2_node.data_mut().ptrs[0].ptr = unsafe { tx.write_block(l1_node) }.unwrap();
            let l2_record_ptr = unsafe { tx.write_block(l2_node) }.unwrap();
            parent.data_mut().level0[1] = unsafe { l2_record_ptr.cast() };
            tx.sync_tree(parent).unwrap();

            Ok(())
        })
        .unwrap();

        // WHEN another entry is added to the full DirList
        fs.tx(|tx| tx.create_node(parent_ptr, "child__0", Node::MODE_FILE, 1, 0))
            .unwrap();

        // THEN the branch splits all the way to the root, increasing the level
        fs.tx(|tx| {
            let parent = tx.read_tree(parent_ptr).unwrap();
            assert!(parent.data().level0[0].is_marker());
            assert_eq!(parent.data().level0[0].addr().level().0, 3);
            assert!(!parent.data().level0[1].addr().is_null());

            let htree_ptr: BlockPtr<HTreeNode<HTreeNode<HTreeNode<DirList>>>> =
                unsafe { parent.data().level0[1].cast() };
            let htree_node = tx.read_block(htree_ptr).unwrap();

            // Note that while a split tries to evenly divide the H-tree entries between the new two sibling nodes,
            // it tries to keep hash collisions together. This unnatural test scenario has a ton of the same max
            // value hash, so those get grouped together, and all our other entries are grouped with the same hash
            // value of zero.
            assert!(!htree_node.data().ptrs[0].is_null());
            assert_eq!(
                htree_node.data().ptrs[0].htree_hash,
                HTreeHash::from_name("__0")
            );
            assert!(!htree_node.data().ptrs[1].is_null());
            assert_eq!(htree_node.data().ptrs[1].htree_hash, HTreeHash::MAX);
            assert!(htree_node.data().ptrs[2].is_null());

            let l3_node = tx.read_block(htree_node.data().ptrs[0].ptr).unwrap();
            let l2_node = tx.read_block(l3_node.data().ptrs[0].ptr).unwrap();
            assert_eq!(
                l2_node.data().ptrs[0].htree_hash,
                HTreeHash::from_name("__0")
            );
            assert_eq!(
                l2_node.data().ptrs[1].htree_hash,
                HTreeHash::from_name("__0")
            );
            assert!(l2_node.data().ptrs[2].is_null());

            Ok(())
        })
        .unwrap();

        // THEN all the colliding files can be listed
        fs.tx(|tx| {
            tx.find_node(parent_ptr, "child__0").unwrap();
            for i in 0..16 {
                let name = format!("child{i:0242}__0");
                let result = tx.find_node(parent_ptr, name.as_str());
                assert!(result.is_ok(), "Could not read {name}");
            }
            Ok(())
        })
        .unwrap();

        // AND the first of the split DirLists has empty space while the second is full
        fs.tx(|tx| {
            let parent = tx.read_tree(parent_ptr).unwrap();
            let htree_ptr: BlockPtr<HTreeNode<HTreeNode<HTreeNode<DirList>>>> =
                unsafe { parent.data().level0[1].cast() };
            let htree_node = tx.read_block(htree_ptr).unwrap();

            assert!(!htree_node.data().ptrs[0].is_null());
            assert_eq!(
                htree_node.data().ptrs[0].htree_hash,
                HTreeHash::from_name("__0")
            );
            assert!(!htree_node.data().ptrs[1].is_null());
            assert_eq!(htree_node.data().ptrs[1].htree_hash, HTreeHash::MAX);
            assert!(htree_node.data().ptrs[2].is_null());

            let l3_node = tx.read_block(htree_node.data().ptrs[0].ptr).unwrap();
            let l2_node = tx.read_block(l3_node.data().ptrs[0].ptr).unwrap();
            assert_eq!(
                l2_node.data().ptrs[0].htree_hash,
                HTreeHash::from_name("__0")
            );
            assert_eq!(
                l2_node.data().ptrs[1].htree_hash,
                HTreeHash::from_name("__0")
            );
            assert!(l2_node.data().ptrs[2].is_null());

            let dir1 = tx.read_block(l2_node.data().ptrs[0].ptr).unwrap();
            for (i, entry) in dir1.data().entries().enumerate() {
                if i == 0 {
                    assert!(
                        !entry.node_ptr().is_null(),
                        "Entry {i} in dir1 should not be null"
                    );
                    assert_eq!(
                        HTreeHash::from_name(entry.name().unwrap()),
                        HTreeHash::from_name("__0"),
                        "Entry {i} with name {}",
                        entry.name().unwrap()
                    );
                } else {
                    assert!(
                        entry.node_ptr().is_null(),
                        "Entry {i} in dir1 should be null"
                    );
                }
            }

            let dir2 = tx.read_block(l2_node.data().ptrs[1].ptr).unwrap();
            for (i, entry) in dir2.data().entries().enumerate() {
                assert!(
                    !entry.node_ptr().is_null(),
                    "Entry {i} in dir2 should not be null"
                );
                assert_eq!(
                    HTreeHash::from_name(entry.name().unwrap()),
                    HTreeHash::from_name("__0"),
                    "Entry {i} with name {}",
                    entry.name().unwrap()
                );
            }
            Ok(())
        })
        .unwrap();
    });
}
