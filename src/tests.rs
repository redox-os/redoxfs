use std::path::Path;
use std::process::Command;
use std::{fs, thread, time};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use crate::{unmount_path, DiskSparse, FileSystem, Node, TreePtr};

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
        let _ = fs.tx(|tx| {
            tx.create_node(
                tree_ptr,
                name,
                Node::MODE_FILE | 0644,
                1,
                0,
            )?;
            tx.remove_node(tree_ptr, name, Node::MODE_FILE)
        }).unwrap();

        assert_eq!(fs.allocator().free(), initially_free);
    });
}
