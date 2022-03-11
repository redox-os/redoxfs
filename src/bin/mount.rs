#![cfg_attr(not(target_os = "redox"), feature(libc))]

#[cfg(not(target_os = "redox"))]
extern crate libc;

#[cfg(target_os = "redox")]
extern crate syscall;

extern crate redoxfs;
extern crate uuid;

use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::process;

use redoxfs::{mount, DiskCache, DiskFile, FileSystem};
use termion::input::TermRead;
use uuid::Uuid;

#[cfg(target_os = "redox")]
extern "C" fn unmount_handler(_s: usize) {
    use std::sync::atomic::Ordering;
    redoxfs::IS_UMT.store(1, Ordering::SeqCst);
}

#[cfg(target_os = "redox")]
//set up a signal handler on redox, this implements unmounting. I have no idea what sa_flags is
//for, so I put 2. I don't think 0,0 is a valid sa_mask. I don't know what i'm doing here. When u
//send it a sigkill, it shuts off the filesystem
fn setsig() {
    use syscall::{sigaction, SigAction, SigActionFlags, SIGTERM};

    let sig_action = SigAction {
        sa_handler: Some(unmount_handler),
        sa_mask: [0, 0],
        sa_flags: SigActionFlags::empty(),
    };

    sigaction(SIGTERM, Some(&sig_action), None).unwrap();
}

#[cfg(not(target_os = "redox"))]
// on linux, this is implemented properly, so no need for this unscrupulous nonsense!
fn setsig() {}

#[cfg(not(target_os = "redox"))]
fn fork() -> isize {
    unsafe { libc::fork() as isize }
}

#[cfg(not(target_os = "redox"))]
fn pipe(pipes: &mut [i32; 2]) -> isize {
    unsafe { libc::pipe(pipes.as_mut_ptr()) as isize }
}

#[cfg(not(target_os = "redox"))]
fn capability_mode() {}

#[cfg(not(target_os = "redox"))]
fn bootloader_password() -> Option<Vec<u8>> {
    None
}

#[cfg(target_os = "redox")]
fn fork() -> isize {
    unsafe { syscall::Error::mux(syscall::clone(syscall::CloneFlags::empty())) as isize }
}

#[cfg(target_os = "redox")]
fn pipe(pipes: &mut [usize; 2]) -> isize {
    syscall::Error::mux(syscall::pipe2(pipes, 0)) as isize
}

#[cfg(target_os = "redox")]
fn capability_mode() {
    syscall::setrens(0, 0).expect("redoxfs: failed to enter null namespace");
}

#[cfg(target_os = "redox")]
fn bootloader_password() -> Option<Vec<u8>> {
    let addr_env = env::var_os("REDOXFS_PASSWORD_ADDR")?;
    let size_env = env::var_os("REDOXFS_PASSWORD_SIZE")?;

    let addr = usize::from_str_radix(
        addr_env.to_str().expect("REDOXFS_PASSWORD_ADDR not valid"),
        16,
    )
    .expect("failed to parse REDOXFS_PASSWORD_ADDR");

    let size = usize::from_str_radix(
        size_env.to_str().expect("REDOXFS_PASSWORD_SIZE not valid"),
        16,
    )
    .expect("failed to parse REDOXFS_PASSWORD_SIZE");

    let mut password = Vec::with_capacity(size);
    unsafe {
        let password_map = syscall::physmap(addr, size, syscall::PhysmapFlags::empty())
            .expect("failed to map REDOXFS_PASSWORD");

        for i in 0..size {
            password.push(*((password_map + i) as *const u8));
        }

        let _ = syscall::physunmap(password_map);
    }
    Some(password)
}

fn usage() {
    println!("redoxfs [--uuid] [disk or uuid] [mountpoint] [block in hex]");
}

enum DiskId {
    Path(String),
    Uuid(Uuid),
}

fn filesystem_by_path(
    path: &str,
    block_opt: Option<u64>,
) -> Option<(String, FileSystem<DiskCache<DiskFile>>)> {
    println!("redoxfs: opening {}", path);
    let attempts = 10;
    for attempt in 0..=attempts {
        let password_opt = if attempt > 0 {
            eprint!("redoxfs: password: ");

            let password = io::stdin()
                .read_passwd(&mut io::stderr())
                .unwrap()
                .unwrap_or(String::new());

            eprintln!();

            if password.is_empty() {
                eprintln!("redoxfs: empty password, giving up");

                // Password is empty, exit loop
                break;
            }

            Some(password.into_bytes())
        } else {
            bootloader_password()
        };

        match DiskFile::open(&path).map(|image| DiskCache::new(image)) {
            Ok(disk) => match redoxfs::FileSystem::open(
                disk,
                password_opt.as_ref().map(|x| x.as_slice()),
                block_opt,
                true,
            ) {
                Ok(filesystem) => {
                    println!(
                        "redoxfs: opened filesystem on {} with uuid {}",
                        path,
                        Uuid::from_bytes(&filesystem.header.uuid())
                            .unwrap()
                            .hyphenated()
                    );

                    return Some((path.to_string(), filesystem));
                }
                Err(err) => match err.errno {
                    syscall::ENOKEY => {
                        if password_opt.is_some() {
                            println!("redoxfs: incorrect password ({}/{})", attempt, attempts);
                        }
                    }
                    _ => {
                        println!("redoxfs: failed to open filesystem {}: {}", path, err);
                        break;
                    }
                },
            },
            Err(err) => {
                println!("redoxfs: failed to open image {}: {}", path, err);
                break;
            }
        }
    }
    None
}

#[cfg(not(target_os = "redox"))]
fn filesystem_by_uuid(
    _uuid: &Uuid,
    _block_opt: Option<u64>,
) -> Option<(String, FileSystem<DiskCache<DiskFile>>)> {
    None
}

#[cfg(target_os = "redox")]
fn filesystem_by_uuid(
    uuid: &Uuid,
    block_opt: Option<u64>,
) -> Option<(String, FileSystem<DiskCache<DiskFile>>)> {
    use std::fs;

    match fs::read_dir(":") {
        Ok(entries) => {
            for entry_res in entries {
                if let Ok(entry) = entry_res {
                    if let Ok(path) = entry.path().into_os_string().into_string() {
                        let scheme = path.trim_start_matches(':').trim_matches('/');
                        if scheme.starts_with("disk") {
                            println!("redoxfs: found scheme {}", scheme);
                            match fs::read_dir(&format!("{}:", scheme)) {
                                Ok(entries) => {
                                    for entry_res in entries {
                                        if let Ok(entry) = entry_res {
                                            if let Ok(path) =
                                                entry.path().into_os_string().into_string()
                                            {
                                                println!("redoxfs: found path {}", path);
                                                if let Some((path, filesystem)) =
                                                    filesystem_by_path(&path, block_opt)
                                                {
                                                    if &filesystem.header.uuid() == uuid.as_bytes()
                                                    {
                                                        println!(
                                                            "redoxfs: filesystem on {} matches uuid {}",
                                                            path,
                                                            uuid.hyphenated()
                                                        );
                                                        return Some((path, filesystem));
                                                    } else {
                                                        println!(
                                                            "redoxfs: filesystem on {} does not match uuid {}",
                                                            path,
                                                            uuid.hyphenated()
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(err) => {
                                    println!("redoxfs: failed to list '{}': {}", scheme, err);
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(err) => {
            println!("redoxfs: failed to list schemes: {}", err);
        }
    }

    None
}

fn daemon(disk_id: &DiskId, mountpoint: &str, block_opt: Option<u64>, mut write: File) -> ! {
    setsig();

    let filesystem_opt = match *disk_id {
        DiskId::Path(ref path) => filesystem_by_path(path, block_opt),
        DiskId::Uuid(ref uuid) => filesystem_by_uuid(uuid, block_opt),
    };

    if let Some((path, filesystem)) = filesystem_opt {
        match mount(filesystem, &mountpoint, |mounted_path| {
            capability_mode();

            println!(
                "redoxfs: mounted filesystem on {} to {}",
                path,
                mounted_path.display()
            );
            let _ = write.write(&[0]);
        }) {
            Ok(()) => {
                process::exit(0);
            }
            Err(err) => {
                println!(
                    "redoxfs: failed to mount {} to {}: {}",
                    path, mountpoint, err
                );
            }
        }
    }

    match *disk_id {
        DiskId::Path(ref path) => {
            println!("redoxfs: not able to mount path {}", path);
        }
        DiskId::Uuid(ref uuid) => {
            println!("redoxfs: not able to mount uuid {}", uuid.hyphenated());
        }
    }

    let _ = write.write(&[1]);
    process::exit(1);
}

fn main() {
    env_logger::init();

    let mut args = env::args().skip(1);

    let disk_id = match args.next() {
        Some(arg) => {
            if arg == "--uuid" {
                let uuid = match args.next() {
                    Some(arg) => match Uuid::parse_str(&arg) {
                        Ok(uuid) => uuid,
                        Err(err) => {
                            println!("redoxfs: invalid uuid '{}': {}", arg, err);
                            usage();
                            process::exit(1);
                        }
                    },
                    None => {
                        println!("redoxfs: no uuid provided");
                        usage();
                        process::exit(1);
                    }
                };

                DiskId::Uuid(uuid)
            } else {
                DiskId::Path(arg)
            }
        }
        None => {
            println!("redoxfs: no disk provided");
            usage();
            process::exit(1);
        }
    };

    let mountpoint = match args.next() {
        Some(arg) => arg,
        None => {
            println!("redoxfs: no mountpoint provided");
            usage();
            process::exit(1);
        }
    };

    let block_opt = match args.next() {
        Some(arg) => match u64::from_str_radix(&arg, 16) {
            Ok(block) => Some(block),
            Err(err) => {
                println!("redoxfs: invalid block '{}': {}", arg, err);
                usage();
                process::exit(1);
            }
        },
        None => None,
    };

    let mut pipes = [0; 2];
    if pipe(&mut pipes) == 0 {
        let mut read = unsafe { File::from_raw_fd(pipes[0] as RawFd) };
        let write = unsafe { File::from_raw_fd(pipes[1] as RawFd) };

        let pid = fork();
        if pid == 0 {
            drop(read);

            daemon(&disk_id, &mountpoint, block_opt, write);
        } else if pid > 0 {
            drop(write);

            let mut res = [0];
            read.read_exact(&mut res).unwrap();

            process::exit(res[0] as i32);
        } else {
            panic!("redoxfs: failed to fork");
        }
    } else {
        panic!("redoxfs: failed to create pipe");
    }
}
