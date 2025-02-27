use crate::{unmount_path, DiskFile, DiskSparse, FileSystem, Node, TreePtr};
use core::time::Duration;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
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
                let res = callback(&real_path);
                let real_path = real_path.to_str().unwrap();

                if cfg!(target_os = "redox") {
                    dbg!(fs::remove_file(dbg!(format!(":{}", real_path)))).unwrap();
                } else {
                    if !dbg!(Command::new("sync").status()).unwrap().success() {
                        panic!("sync failed");
                    }

                    if !unmount_path(real_path).is_ok() {
                        panic!("umount failed");
                    }
                }

                res
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
fn create_remove_should_not_increase_size() {
    with_redoxfs(|mut fs| {
        let initially_free = fs.allocator().free();

        let tree_ptr = TreePtr::<Node>::root();
        let name = "test";
        let _ = fs
            .tx(|tx| {
                tx.create_node(tree_ptr, name, Node::MODE_FILE | 0644, 1, 0)?;
                tx.remove_node(tree_ptr, name, Node::MODE_FILE)
            })
            .unwrap();

        assert_eq!(fs.allocator().free(), initially_free);
    });
}

#[test]
fn many_create_remove_should_not_increase_size() {
    with_redoxfs(|mut fs| {
        let initially_free = fs.allocator().free();
        let tree_ptr = TreePtr::<Node>::root();
        let name = "test";

        // Iterate over 255 times to prove deleted files don't retain space within the node tree
        for i in 0..600 {
            let _ = fs
                .tx(|tx| {
                    tx.create_node(tree_ptr, &format!("{}{}", name, i), Node::MODE_FILE | 0644, 1, 0)?;
                    tx.remove_node(tree_ptr, &format!("{}{}", name, i), Node::MODE_FILE)
                })
                .unwrap();
        }

        // If we don't syunc with squash, then every ~21 iterations, the size increases by 1
        let _ = fs
        .tx(|tx|{
            tx.sync(true)
        });

        // Any value greater than 0 indicates a memory leak
        let diff = initially_free - fs.allocator().free();
        assert_eq!(diff, 0);
    });
}

#[test]
fn many_creates_should_perform_consistently() {
    with_redoxfs(|mut fs| {
        let tree_ptr = TreePtr::<Node>::root();
        let name = "test";
        let mut count = 0;

        // Time how long it takes to create the first file
        let start = time::Instant::now();
        count += 1;
        let _ = fs
            .tx(|tx| {
                tx.create_node(tree_ptr, &format!("{}{}", name, "first"), Node::MODE_FILE | 0644, 1, 0)
            })
            .unwrap();
        let first_duration = time::Instant::now() - start;

        // Create a bunch of files to populate the file system
        for i in 0..5000 {
            count += 1;
            let _ = fs
                .tx(|tx| {
                    tx.create_node(tree_ptr, &format!("{}{}", name, i), Node::MODE_FILE | 0644, 1, 0)
                })
                .unwrap();
        }

        // Time how long it takes to create the last file
        let start = time::Instant::now();
        count += 1;
        let _ = fs
            .tx(|tx| {
                tx.create_node(tree_ptr, &format!("{}{}", name, "last"), Node::MODE_FILE | 0644, 1, 0)
            })
            .unwrap();
        let last_duration = time::Instant::now() - start;

        let diff_secs = (last_duration.as_secs() as i128 - first_duration.as_secs() as i128).abs();
        let diff_nanosecs = (last_duration.as_nanos() as i128 - first_duration.as_nanos() as i128).abs();
        let duration_diff = Duration::new(diff_secs as u64, diff_nanosecs as u32);
        let duration_max = Duration::from_millis(1);
        println!("file 1 duration: {:?}", first_duration);
        println!("file {count} duration: {:?}", last_duration);
        println!("duration_diff: {:?}", duration_diff);
        println!();
        assert!(duration_max.ge(&duration_diff), "duration difference exceeds {:?}: {:?}", duration_max, duration_diff);
    });
}

#[test]
fn many_create_remove_across_transactions_should_not_increase_size_repeat() -> Result<(), Box<dyn std::error::Error>> {
    let disk_path = "image_slow.bin";
    let disk = DiskFile::open(dbg!(&disk_path)).unwrap();
    let mut fs = FileSystem::open(disk, None, None, true)?;

    let initially_free = fs.allocator().free();

    let tree_ptr = TreePtr::<Node>::root();
    let name = "test";
    let start_time = time::Instant::now();

    for i in 0..1 {
        let _ = fs
            .tx(|tx| {
                tx.create_node(tree_ptr, &format!("{}{}", name, i), Node::MODE_FILE | 0644, 1, 0)?;
                tx.remove_node(tree_ptr, &format!("{}{}", name, i), Node::MODE_FILE)?;
                tx.sync(true)
            })
            .unwrap();
    }

    let duration = time::Instant::now() - start_time;
    eprintln!("{duration:?}");
    let diff = initially_free - fs.allocator().free();
    assert_eq!(diff, 0);
    Ok(())
}

#[test]
fn many_create_remove_across_transactions_should_not_increase_size_init() {
    with_redoxfs(|mut fs| {
        let initially_free = fs.allocator().free();

        let tree_ptr = TreePtr::<Node>::root();
        let name = "test";
        let mut start_time = time::Instant::now();

        for i in 0..255000 {
            // if i >= 253 {
                // println!("iteration {i}: {:?}", fs.allocator().levels());
            // }
            if i % 255 == 0 {
                let diff = initially_free - fs.allocator().free();
                let now = time::Instant::now();
                let duration = now - start_time;
                start_time = now;
                eprintln!("iteration {i}: {diff} {duration:?}");
            }

            let _ = fs
                .tx(|tx| {
                    tx.create_node(tree_ptr, &format!("{}{}", name, i), Node::MODE_FILE | 0644, 1, 0)?;
                    tx.remove_node(tree_ptr, &format!("{}{}", name, i), Node::MODE_FILE)
                })
                .unwrap();

            if i % 20 == 0 {
                let _ = fs
                    .tx(|tx| {
                        tx.sync(true)
                     })
                    .unwrap();
            }
        }

        fs.tx(|tx| {
            tx.sync(true)
        })
        .unwrap();

        let diff = initially_free - fs.allocator().free();
        assert_eq!(diff, 0);
    });
}