use redox_scheme::{scheme::SchemeSync, RequestKind, Response, SignalBehavior, Socket};
use std::io;
use std::path::Path;
use std::sync::atomic::Ordering;

use crate::{Disk, FileSystem, IS_UMT};

use self::scheme::FileScheme;

pub mod resource;
pub mod scheme;

//FIXME: mut callback is not mut
#[allow(unused_mut)]

pub fn mount<D, P, T, F>(filesystem: FileSystem<D>, mountpoint: P, mut callback: F) -> io::Result<T>
where
    D: Disk,
    P: AsRef<Path>,
    F: FnOnce(&Path) -> T,
{
    let mountpoint = mountpoint.as_ref();
    let socket = Socket::create()?;

    let scheme_name = format!("{}", mountpoint.display());
    let mounted_path = format!("/scheme/{}", mountpoint.display());

    let mut scheme = FileScheme::new(scheme_name, mounted_path.clone(), filesystem, &socket);

    redox_scheme::scheme::register_sync_scheme(
        &socket,
        &format!("{}", mountpoint.display()),
        &mut scheme,
    )?;

    let res = callback(Path::new(&mounted_path));

    while IS_UMT.load(Ordering::SeqCst) == 0 {
        let req = match socket.next_request(SignalBehavior::Restart)? {
            None => break,
            Some(req) => {
                match req.kind() {
                    RequestKind::Call(r) => r,
                    RequestKind::SendFd(sendfd_request) => {
                        let result = scheme.on_sendfd(&sendfd_request);
                        let response = Response::new(result, sendfd_request);

                        if !socket.write_response(response, SignalBehavior::Restart)? {
                            break;
                        }
                        continue;
                    }
                    RequestKind::OnClose { id } => {
                        scheme.on_close(id);
                        continue;
                    }
                    _ => {
                        // TODO: Redoxfs does not yet support asynchronous file IO. It might still make
                        // sense to implement cancellation for huge buffers, e.g. dd bs=1G
                        continue;
                    }
                }
            }
        };
        let response = req.handle_sync(&mut scheme);

        if !socket.write_response(response, SignalBehavior::Restart)? {
            break;
        }
    }

    // Cleanup on unmount
    scheme.fs.cleanup()?;

    Ok(res)
}
