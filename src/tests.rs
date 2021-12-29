use std::ops::DerefMut;
use std::path::Path;
use std::process::Command;
use std::{fs, sync, thread, time};

use crate::{DiskSparse, FileSystem};

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

                    let status_res = if cfg!(target_os = "linux") {
                        Command::new("fusermount")
                            .arg("-u")
                            .arg(mount_path)
                            .status()
                    } else {
                        Command::new("umount").arg(mount_path).status()
                    };

                    let status = dbg!(status_res).unwrap();
                    if !status.success() {
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
            let fd = dbg!(syscall::open(
                path.to_str().unwrap(),
                syscall::O_CREAT | syscall::O_RDWR | syscall::O_CLOEXEC
            ))
            .unwrap();

            let map = unsafe {
                slice::from_raw_parts_mut(
                    dbg!(syscall::fmap(
                        fd,
                        &syscall::Map {
                            offset: 0,
                            size: 128,
                            flags: syscall::PROT_READ | syscall::PROT_WRITE,
                            address: 0,
                        }
                    ))
                    .unwrap() as *mut u8,
                    128,
                )
            };

            // Maps should be available after closing
            assert_eq!(dbg!(syscall::close(fd)), Ok(0));

            for i in 0..128 {
                if write {
                    map[i as usize] = i;
                }
                assert_eq!(map[i as usize], i);
            }

            //TODO: add msync
            unsafe {
                assert_eq!(
                    dbg!(syscall::funmap(map.as_mut_ptr() as usize, map.len())),
                    Ok(0)
                );
            }
        };

        mmap_inner(true);
        mmap_inner(false);
    })
}
