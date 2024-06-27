//! Fuzzer that exercises random file system operations against a FUSE-mounted redoxfs.

#![no_main]

use anyhow::{ensure, Result};
use fuser;
use libfuzzer_sys::{arbitrary::Arbitrary, fuzz_target, Corpus};
use nix::sys::statvfs::statvfs;
use std::{
    fs::{self, File, FileTimes, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{self as unix_fs, PermissionsExt},
    path::{Path, PathBuf},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempfile;

use redoxfs::{mount::fuse::Fuse, DiskSparse, FileSystem};

/// Maximum size for files and buffers. Chosen arbitrarily with fuzzing performance in mind.
const MAX_SIZE: u64 = 10_000_000;
/// Limit on the number of remounts in a single test case. Chosen arbitrarily with fuzzing
/// performance in mind: remounts are costly.
const MAX_MOUNT_SEQUENCES: usize = 3;

/// An operation to be performed by the fuzzer.
#[derive(Arbitrary, Clone, Debug)]
enum Operation {
    Chown {
        path: PathBuf,
        uid: Option<u32>,
        gid: Option<u32>,
    },
    CreateDir {
        path: PathBuf,
    },
    HardLink {
        original: PathBuf,
        link: PathBuf,
    },
    Metadata {
        path: PathBuf,
    },
    Read {
        path: PathBuf,
    },
    ReadDir {
        path: PathBuf,
    },
    ReadLink {
        path: PathBuf,
    },
    RemoveDir {
        path: PathBuf,
    },
    RemoveFile {
        path: PathBuf,
    },
    Rename {
        from: PathBuf,
        to: PathBuf,
    },
    SeekRead {
        path: PathBuf,
        seek_pos: u64,
        buf_size: usize,
    },
    SeekWrite {
        path: PathBuf,
        seek_pos: u64,
        buf_size: usize,
    },
    SetLen {
        path: PathBuf,
        size: u64,
    },
    SetPermissions {
        path: PathBuf,
        readonly: Option<bool>,
        mode: Option<u32>,
    },
    SetTimes {
        path: PathBuf,
        accessed_since_epoch: Option<Duration>,
        modified_since_epoch: Option<Duration>,
    },
    Statvfs {},
    SymLink {
        original: PathBuf,
        link: PathBuf,
    },
    Write {
        path: PathBuf,
        buf_size: usize,
    },
}

/// Parameters for mounting the file system and operations to be performed afterwards.
#[derive(Arbitrary, Clone, Debug)]
struct MountSequence {
    squash: bool,
    operations: Vec<Operation>,
}

/// The whole input to a single fuzzer invocation.
#[derive(Arbitrary, Clone, Debug)]
struct TestCase {
    disk_size: u64,
    reserved_size: u64,
    mount_sequences: Vec<MountSequence>,
}

/// Creates the disk for backing the Redoxfs.
fn create_disk(temp_path: &Path, disk_size: u64) -> DiskSparse {
    let disk_path = temp_path.join("disk.img");
    DiskSparse::create(disk_path, disk_size).unwrap()
}

/// Creates an empty Redoxfs.
fn create_redoxfs(disk: DiskSparse, reserved_size: u64) -> bool {
    let password = None;
    let reserved = vec![0; reserved_size as usize];
    let ctime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    FileSystem::create_reserved(
        disk,
        password,
        &reserved,
        ctime.as_secs(),
        ctime.subsec_nanos(),
    )
    .is_ok()
}

/// Mounts an existing Redoxfs, runs the callback and performs the unmount.
fn with_redoxfs_mount<F>(temp_path: &Path, disk: DiskSparse, squash: bool, callback: F)
where
    F: FnOnce(&Path) + Send + 'static,
{
    let password = None;
    let block = None;
    let mut fs = FileSystem::open(disk, password, block, squash).unwrap();

    let mount_path = temp_path.join("mount");
    fs::create_dir_all(&mount_path).unwrap();
    let mut session = fuser::Session::new(Fuse { fs: &mut fs }, &mount_path, &[]).unwrap();
    let mut unmounter = session.unmount_callable();

    let join_handle = thread::spawn(move || {
        callback(&mount_path);
        unmounter.unmount().unwrap();
    });

    session.run().unwrap();
    join_handle.join().unwrap();
}

fn get_path_within_fs(fs_path: &Path, path_to_add: &Path) -> Result<PathBuf> {
    ensure!(path_to_add.is_relative());
    ensure!(path_to_add
        .components()
        .all(|c| c != std::path::Component::ParentDir));
    Ok(fs_path.join(path_to_add))
}

fn do_operation(fs_path: &Path, op: &Operation) -> Result<()> {
    match op {
        Operation::Chown { path, uid, gid } => {
            let path = get_path_within_fs(fs_path, path)?;
            unix_fs::chown(path, *uid, *gid)?;
        }
        Operation::CreateDir { path } => {
            let path = get_path_within_fs(fs_path, path)?;
            fs::create_dir(path)?;
        }
        Operation::HardLink { original, link } => {
            let original = get_path_within_fs(fs_path, original)?;
            let link = get_path_within_fs(fs_path, link)?;
            fs::hard_link(original, link)?;
        }
        Operation::Metadata { path } => {
            let path = get_path_within_fs(fs_path, path)?;
            fs::metadata(path)?;
        }
        Operation::Read { path } => {
            let path = get_path_within_fs(fs_path, path)?;
            fs::read(path)?;
        }
        Operation::ReadDir { path } => {
            let path = get_path_within_fs(fs_path, path)?;
            let _ = fs::read_dir(path)?.count();
        }
        Operation::ReadLink { path } => {
            let path = get_path_within_fs(fs_path, path)?;
            fs::read_link(path)?;
        }
        Operation::RemoveDir { path } => {
            let path = get_path_within_fs(fs_path, path)?;
            fs::remove_dir(path)?;
        }
        Operation::RemoveFile { path } => {
            let path = get_path_within_fs(fs_path, path)?;
            fs::remove_file(path)?;
        }
        Operation::Rename { from, to } => {
            let from = get_path_within_fs(fs_path, from)?;
            let to = get_path_within_fs(fs_path, to)?;
            fs::rename(from, to)?;
        }
        Operation::SeekRead {
            path,
            seek_pos,
            buf_size,
        } => {
            ensure!(*buf_size as u64 <= MAX_SIZE);
            let path = get_path_within_fs(fs_path, path)?;
            let mut file = File::open(path)?;
            file.seek(SeekFrom::Start(*seek_pos))?;
            let mut buf = vec![0; *buf_size];
            file.read(&mut buf)?;
        }
        Operation::SeekWrite {
            path,
            seek_pos,
            buf_size,
        } => {
            ensure!(*seek_pos <= MAX_SIZE);
            ensure!(*buf_size as u64 <= MAX_SIZE);
            let path = get_path_within_fs(fs_path, path)?;
            let mut file = OpenOptions::new().write(true).open(path)?;
            file.seek(SeekFrom::Start(*seek_pos))?;
            let buf = vec![0; *buf_size];
            file.write(&buf)?;
        }
        Operation::SetLen { path, size } => {
            let path = get_path_within_fs(fs_path, path)?;
            let file = OpenOptions::new().write(true).open(path)?;
            file.set_len(*size)?;
        }
        Operation::SetPermissions {
            path,
            readonly,
            mode,
        } => {
            let path = get_path_within_fs(fs_path, path)?;
            let metadata = fs::metadata(&path)?;
            let mut perms = metadata.permissions();
            if let Some(readonly) = readonly {
                perms.set_readonly(*readonly);
            }
            if let Some(mode) = mode {
                perms.set_mode(*mode);
            }
            fs::set_permissions(path, perms)?;
        }
        Operation::SetTimes {
            path,
            accessed_since_epoch,
            modified_since_epoch,
        } => {
            let path = get_path_within_fs(fs_path, path)?;
            let file = File::options().write(true).open(path)?;
            let mut times = FileTimes::new();
            if let Some(accessed_since_epoch) = accessed_since_epoch {
                if let Some(accessed) = UNIX_EPOCH.checked_add(*accessed_since_epoch) {
                    times = times.set_accessed(accessed);
                }
            }
            if let Some(modified_since_epoch) = modified_since_epoch {
                if let Some(modified) = UNIX_EPOCH.checked_add(*modified_since_epoch) {
                    times = times.set_modified(modified);
                }
            }
            file.set_times(times)?;
        }
        Operation::Statvfs {} => {
            statvfs(fs_path)?;
        }
        Operation::SymLink { original, link } => {
            let original = get_path_within_fs(fs_path, original)?;
            let link = get_path_within_fs(fs_path, link)?;
            unix_fs::symlink(original, link)?;
        }
        Operation::Write { path, buf_size } => {
            ensure!(*buf_size as u64 <= MAX_SIZE);
            let path = get_path_within_fs(fs_path, path)?;
            let buf = vec![0; *buf_size];
            fs::write(path, &buf)?;
        }
    }
    Ok(())
}

fuzz_target!(|test_case: TestCase| -> Corpus {
    if test_case.disk_size > MAX_SIZE
        || test_case.reserved_size > MAX_SIZE
        || test_case.mount_sequences.len() > MAX_MOUNT_SEQUENCES
    {
        return Corpus::Reject;
    }

    let temp_dir = tempfile::Builder::new()
        .prefix("fuse_fuzz_target")
        .tempdir()
        .unwrap();

    #[cfg(feature = "log")]
    eprintln!("create fs");
    let disk = create_disk(temp_dir.path(), test_case.disk_size);
    if !create_redoxfs(disk, test_case.reserved_size) {
        // File system creation failed (e.g., due to insufficient space) so we bail out, still
        // exercising this code path is useful.
        return Corpus::Keep;
    }

    for mount_seq in test_case.mount_sequences.iter() {
        #[cfg(feature = "log")]
        eprintln!("mount fs");

        let disk = create_disk(temp_dir.path(), test_case.disk_size);
        let operations = mount_seq.operations.clone();
        with_redoxfs_mount(temp_dir.path(), disk, mount_seq.squash, move |fs_path| {
            for operation in operations.iter() {
                #[cfg(feature = "log")]
                eprintln!("do operation {operation:?}");

                let _result = do_operation(fs_path, operation);

                #[cfg(feature = "log")]
                eprintln!("operation result {:?}", _result.err());
            }
        });

        #[cfg(feature = "log")]
        eprintln!("unmounted fs");
    }
    Corpus::Keep
});
