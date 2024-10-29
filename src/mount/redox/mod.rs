use std::io;
use std::path::Path;
use std::sync::atomic::Ordering;
use redox_scheme::{RequestKind, SignalBehavior, Socket, V2};

use crate::{Disk, FileSystem, Transaction, IS_UMT};

use self::scheme::FileScheme;

pub mod resource;
pub mod scheme;

pub fn mount<D, P, T, F>(filesystem: FileSystem<D>, mountpoint: P, mut callback: F) -> io::Result<T>
where
    D: Disk,
    P: AsRef<Path>,
    F: FnOnce(&Path) -> T,
{
    let mountpoint = mountpoint.as_ref();
    let socket = Socket::<V2>::create(&format!("{}", mountpoint.display()))?;

    let mounted_path = format!("{}:", mountpoint.display());
    let res = callback(Path::new(&mounted_path));

    let mut scheme = FileScheme::new(format!("{}", mountpoint.display()), filesystem);
    while IS_UMT.load(Ordering::SeqCst) == 0 {
        let req = match socket.next_request(SignalBehavior::Restart)? {
            None => break,
            Some(req) => if let RequestKind::Call(r) = req.kind() {
                r
            } else {
                // TODO: Redoxfs does not yet support asynchronous file IO. It might still make
                // sense to implement cancellation for huge buffers, e.g. dd bs=1G
                continue;
            }
        };
        let response = req.handle_scheme_mut(&mut scheme);

        if !socket.write_response(response, SignalBehavior::Restart)? {
            break;
        }
    }

    // Squash allocations and sync on unmount
    let _ = Transaction::new(&mut scheme.fs).commit(true);

    Ok(res)
}
