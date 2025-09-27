use assert_cmd::cargo::CommandCargoExt;

use core::panic::AssertUnwindSafe;
use redoxfs::{unmount_path, DirEntry, DiskMemory, DiskSparse, FileSystem, Node, TreePtr};

use std::panic::catch_unwind;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use std::thread::sleep;
use std::time::Duration;
use std::{env, fs, time};

static IMAGE_SEQ: AtomicUsize = AtomicUsize::new(0);

fn with_redoxfs<T, F>(callback: F) -> T
where
    T: Send + Sync + 'static,
    F: FnOnce(&str) -> T + Send + Sync + 'static,
{
    let disk_path = format!("image{}.bin", IMAGE_SEQ.fetch_add(1, Relaxed));

    {
        let disk = DiskSparse::create(dbg!(&disk_path), 1024 * 1024 * 1024).unwrap();
        let ctime = dbg!(time::SystemTime::now().duration_since(time::UNIX_EPOCH)).unwrap();
        FileSystem::create(disk, None, ctime.as_secs(), ctime.subsec_nanos()).unwrap();
    }
    let res = callback(&disk_path);

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
        // At redox, we mount on /scheme/ path, no need an empty dir
        if cfg!(not(target_os = "redox")) {
            if !Path::new(&mount_path).exists() {
                dbg!(fs::create_dir(dbg!(&mount_path))).unwrap();
            }
        } else {
            //FIXME: cargo_bin is broken when cross compiling. This is redoxer specific workaround
            env::set_var(
                "CARGO_BIN_EXE_redoxfs",
                "/root/target/x86_64-unknown-redox/debug/redoxfs",
            );
        }
        let mut mount_cmd = Command::cargo_bin("redoxfs").expect("unable to find mount bin");
        mount_cmd.arg("-d").arg(dbg!(&fs)).arg(dbg!(&mount_path));
        let mut child = mount_cmd.spawn().expect("mount failed to run");

        let real_path = if cfg!(target_os = "redox") {
            let real_path = dbg!(Path::new("/scheme").join(&mount_path));
            let mut tries = 0;
            loop {
                if real_path.exists() {
                    break;
                }
                tries += 1;
                if tries == 100 {
                    panic!("Fail to wait for mount")
                }
                sleep(Duration::from_millis(500));
            }
            real_path
        } else {
            sleep(Duration::from_millis(200));
            let r = Path::new(".").join(&mount_path);
            r
        };

        let res = catch_unwind(AssertUnwindSafe(|| callback(&real_path)));

        sleep(Duration::from_millis(200));

        child.kill().expect("Can't kill");

        if cfg!(target_os = "redox") {
            unmount_path(&mount_path).unwrap();
        } else {
            if !dbg!(Command::new("sync").status()).unwrap().success() {
                panic!("sync failed");
            }

            if !unmount_path(&mount_path).is_ok() {
                // There seems to be a race condition where the device can be busy when trying to unmount.
                // So, we pause for a moment and retry. There will still be an error output to the logs
                // for the first failed attempt.
                sleep(Duration::from_millis(200));
                if !unmount_path(&mount_path).is_ok() {
                    panic!("umount failed");
                }
            }
        }

        res.expect("Test failed")
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
        fs::create_dir(&dir_path).expect(&format!("cannot create dir {}", &dir_path.display()));
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
