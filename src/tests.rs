use std::ops::DerefMut;
use std::path::Path;
use std::process::Command;
use std::{fs, sync, thread, time};

use crate::{unmount_path, DiskSparse, FileSystem};

fn with_redoxfs<T, F>(callback: F) -> T
where
    T: Send + Sync + 'static,
    F: FnMut(&Path) -> T + Send + Sync + 'static,
{
    let disk_path = "image.bin";
    let mount_path = "image";

    let res = {
        let disk = DiskSparse::create(dbg!(disk_path), 1024 * 1024 * 1024).unwrap();

        if cfg!(not(target_os = "redox")) {
            if !Path::new(mount_path).exists() {
                dbg!(fs::create_dir(dbg!(mount_path))).unwrap();
            }
        }

        let ctime = dbg!(time::SystemTime::now().duration_since(time::UNIX_EPOCH)).unwrap();
        let fs = FileSystem::create(disk, None, ctime.as_secs(), ctime.subsec_nanos()).unwrap();

        let callback_mutex = sync::Arc::new(sync::Mutex::new(callback));
        let join_handle = crate::mount(fs, dbg!(mount_path), move |real_path| {
            let callback_mutex = callback_mutex.clone();
            let real_path = real_path.to_owned();
            thread::spawn(move || {
                let res = {
                    let mut callback_guard = callback_mutex.lock().unwrap();
                    let callback = callback_guard.deref_mut();
                    callback(&real_path)
                };

                if cfg!(target_os = "redox") {
                    dbg!(fs::remove_file(dbg!(format!(":{}", mount_path)))).unwrap();
                } else {
                    if !dbg!(Command::new("sync").status()).unwrap().success() {
                        panic!("sync failed");
                    }

                    if !unmount_path(mount_path).is_ok() {
                        panic!("umount failed");
                    }
                }

                res
            })
        })
        .unwrap();

        join_handle.join().unwrap()
    };

    dbg!(fs::remove_file(dbg!(disk_path))).unwrap();

    if cfg!(not(target_os = "redox")) {
        dbg!(fs::remove_dir(dbg!(mount_path))).unwrap();
    }

    res
}

#[test]
fn simple() {
    with_redoxfs(|path| {
        dbg!(fs::create_dir(&path.join("test"))).unwrap();
    })
}

#[cfg(target_os = "redox")]
#[test]
fn mmap() {
    use syscall;

    //TODO
    with_redoxfs(|path| {
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
