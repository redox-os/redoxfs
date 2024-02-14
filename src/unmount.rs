use std::{
    fs,
    io::{self},
    process::{Command, ExitStatus},
};

fn unmount_linux_path(mount_path: &str) -> io::Result<ExitStatus> {
    // Different distributions can have various fusermount binaries. Try
    // them all.
    let commands = ["fusermount", "fusermount3"];

    for command in commands {
        let status = Command::new(command).arg("-u").arg(mount_path).status();
        if status.is_ok() {
            return status;
        }
        if let Err(ref e) = status {
            if e.kind() == io::ErrorKind::NotFound {
                continue;
            }
        }
    }

    // Unmounting failed since no suitable command was found
    Err(std::io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "Unable to locate any fusermount binaries. Tried {:?}. Is fuse installed?",
            commands
        ),
    ))
}

pub fn unmount_path(mount_path: &str) -> Result<(), io::Error> {
    if cfg!(target_os = "redox") {
        fs::remove_file(format!(":{}", mount_path))?
    } else {
        let status_res = if cfg!(target_os = "linux") {
            unmount_linux_path(mount_path)
        } else {
            Command::new("umount").arg(mount_path).status()
        };

        let status = status_res?;
        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "redoxfs umount failed",
            ));
        }
    }

    Ok(())
}
