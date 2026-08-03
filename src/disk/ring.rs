use std::collections::HashMap;
use std::os::fd::IntoRawFd;
use std::ptr::NonNull;

use libredox::{flag, Fd};
use redox_buffer_pool::{AllocationStrategy, NoHandle};
use redox_rings::op::{DiskOpCqe, DiskOpKind, DiskOpSqe};
use redox_rings::raw::RingPushError;
use redox_rings::sync::{BlockingConsumer, BlockingProducer, FutexWaitResult, WaitNotify};
use syscall::error::{Error, Result};
use syscall::CallFlags;
use syscall::TimeSpec;
use syscall::EIO;
use syscall::ENOMEM;
use zerocopy::IntoBytes;

use super::Disk;
use crate::DiskFile;
use crate::SIGNATURE;

const POOL_SIZE: u32 = 4 * 1024 * 1024; // 4 MiB pool

type BufferPool = redox_buffer_pool::BufferPool<'static, u32, NoHandle, ()>;
type BufferSlice<'pool> = redox_buffer_pool::BufferSlice<'pool, u32, NoHandle, ()>;

struct Pipe(Fd);

impl WaitNotify for Pipe {
    fn wait_on_tail(
        &self,
        _expected_tail: u32,
        _deadline_opt: Option<&TimeSpec>,
    ) -> FutexWaitResult {
        unimplemented!("notify_on_tail is not implemented for Pipe")
    }
    fn notify_on_tail(&self) {
        if let Err(err) = self.0.write(&[0]) {
            log::error!("Pipe::notify_on_tail() failed: {err}");
        }
    }
    fn wait_on_head(
        &self,
        _expected_head: u32,
        _deadline_opt: Option<&TimeSpec>,
    ) -> FutexWaitResult {
        unimplemented!("wait_on_head is not implemented for Pipe")
    }
    fn notify_on_head(&self) {
        unimplemented!("notify_on_head is not implemented for Pipe")
    }
}

pub struct DiskRing {
    sq: BlockingProducer<DiskOpSqe>,
    cq: BlockingConsumer<DiskOpCqe>,
    shm_base: *mut u8,
    allocator: BufferPool,
    next_id: u64,
    disk_size: u64,
    offset: u64,
    #[allow(unused, reason = "closed on drop")]
    ring_fd: Fd,
    pipe: Pipe,
}

impl DiskRing {
    pub fn from_fd(ring_fd: Fd, df: DiskFile, disk_size: u64) -> Result<Self> {
        use libredox::call::{mmap, MmapArgs};
        use redox_rings::op::{RingCallVerb, RingSetupFlags, RingSetupParams};

        let disk_fd = Fd::new(df.file.into_raw_fd() as usize);

        let mut params = RingSetupParams {
            nr_sq_entries: 256,
            // The `CQSIZE` flag is not set, so the scheme will fill in this field for us.
            nr_cq_entries: 0,
            flags: RingSetupFlags::empty().bits(),
            pool_size: POOL_SIZE,
        };

        ring_fd.call_rw(
            params.as_mut_bytes(),
            CallFlags::empty(),
            &[RingCallVerb::Setup as u64],
        )?;

        let fixed_rtbl_req = [ring_fd.raw(), disk_fd.raw()];
        libredox::call::call_wo(
            fixed_rtbl_req.as_slice(),
            &[],
            CallFlags::empty(),
            &[RingCallVerb::SetFileTable as u64],
        )?;
        drop(disk_fd);

        // mmap the shared DMA/shm pool
        let shm_ptr = unsafe {
            mmap(MmapArgs {
                addr: std::ptr::null_mut(),
                length: POOL_SIZE as usize,
                prot: flag::PROT_READ | flag::PROT_WRITE,
                flags: flag::MAP_SHARED,
                fd: ring_fd.raw(),
                offset: 0,
            })
            .map_err(|_| Error::new(EIO))? as *mut u8
        };

        let mut fd_buf = [usize::MAX; 3]; // [sq_shm_fd, cq_shm_fd, pipe_fd]
        ring_fd
            .call_ro(
                fd_buf.as_mut_bytes(),
                CallFlags::FD | CallFlags::FD_UPPER,
                &[],
            )
            .map_err(|_| Error::new(EIO))?;

        let (sq_shm_fd, cq_shm_fd, pipe) = (
            Fd::new(fd_buf[0]),
            Fd::new(fd_buf[1]),
            Fd::new(fd_buf[2]).openat("write", 0, 0)?,
        );

        let sq =
            BlockingProducer::<DiskOpSqe>::from_fd(sq_shm_fd, false, Some(params.nr_sq_entries))
                .map_err(|_| Error::new(EIO))?;

        let cq =
            BlockingConsumer::<DiskOpCqe>::from_fd(cq_shm_fd, false, Some(params.nr_cq_entries))
                .map_err(|_| Error::new(EIO))?;

        let allocator = {
            let pool = BufferPool::new(None);
            let handle = pool
                .begin_expand(params.pool_size)
                .map_err(|_| Error::new(EIO))?;

            unsafe {
                handle.initialize(NonNull::new(shm_ptr).ok_or(Error::new(ENOMEM))?, ());
            }
            pool
        };

        let mut ring = Self {
            sq,
            cq,
            ring_fd,
            shm_base: shm_ptr,
            allocator,
            next_id: 0,
            disk_size,
            offset: 0,
            pipe: Pipe(pipe),
        };

        // Scan for RedoxFS signature
        // Assuming 512 byte sectors for NVMe
        let candidates = [0, 2048];
        for &start_lba in &candidates {
            let mut buf = [0u8; 4096];
            if let Ok(_) = unsafe { ring.read_at(start_lba, &mut buf) } {
                if &buf[0..8] == SIGNATURE {
                    ring.offset = start_lba;
                    break;
                }
            }
        }

        Ok(ring)
    }

    fn disk_op<'a, B, I, P, C>(
        &'a mut self,
        opcode: DiskOpKind,
        batch: B,
        prepare: P,
        complete: C,
    ) -> Result<usize>
    where
        B: Iterator<Item = (u64, I)>,
        I: AsRef<[u8]>,
        P: Fn(&I, &mut BufferSlice<'a>),
        C: Fn(&mut I, &BufferSlice<'a>),
    {
        let mut total_processed = 0;
        let mut pending = HashMap::new();
        let mut notified = true;

        let process_cqe = |cqe: DiskOpCqe, pending: &mut HashMap<u64, (I, BufferSlice<'a>)>| {
            if let Some((mut item, buf)) = pending.remove(&cqe.user_data) {
                complete(&mut item, &buf);
            }
        };

        let notify_on_tail = |notified: &mut bool, cq: &mut BlockingProducer<DiskOpSqe>| {
            if cq.inner.header.is_wait_head() {
                self.pipe.notify_on_tail();
            }

            *notified = true;
        };

        for (lba, chunk) in batch {
            let len = chunk.as_ref().len();

            let mut buf = loop {
                if let Some(buf) = self.allocator.acquire_borrowed_slice(
                    u32::try_from(len).map_err(|_| Error::new(ENOMEM))?,
                    1,
                    AllocationStrategy::Optimal,
                ) {
                    break buf;
                }
                if !notified {
                    notify_on_tail(&mut notified, &mut self.sq);
                }
                match self.cq.pop(None) {
                    Ok(cqe) => process_cqe(cqe, &mut pending),
                    Err(_) => return Err(Error::new(EIO)),
                }
            };

            prepare(&chunk, &mut buf);

            let new_id = self.next_id;
            self.next_id += 1;
            let sqe = DiskOpSqe {
                opcode: opcode as u8,
                block: lba,
                buf_offset: buf.offset(),
                buf_len: len as u32,
                user_data: new_id,
                file_idx: 0,
                pad: [0; 3],
            };

            pending.insert(new_id, (chunk, buf));

            loop {
                match self.sq.inner.push_back(sqe.clone()) {
                    Ok(_) => break,
                    Err(RingPushError::Full(_)) => {
                        if !notified {
                            notify_on_tail(&mut notified, &mut self.sq);
                        }
                        match self.cq.pop(None) {
                            Ok(cqe) => process_cqe(cqe, &mut pending),
                            Err(_) => return Err(Error::new(EIO)),
                        }
                    }
                    Err(RingPushError::Broken(_)) => return Err(Error::new(EIO)),
                }
            }

            notified = false;
            total_processed += len;
        }

        if !notified {
            notify_on_tail(&mut notified, &mut self.sq);
        }

        while !pending.is_empty() {
            match self.cq.pop(None) {
                Ok(cqe) => process_cqe(cqe, &mut pending),
                Err(_) => return Err(Error::new(EIO)),
            }
        }

        Ok(total_processed)
    }
}

impl Disk for DiskRing {
    unsafe fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        self.disk_op(
            DiskOpKind::Read,
            core::iter::once((block * 8 + self.offset, buffer)),
            |_buf, _cmd_buf| {},
            |buf, cmd_buf| buf.copy_from_slice(cmd_buf),
        )
    }

    unsafe fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        self.write_at_batched(&[(block, buffer)])
    }

    unsafe fn write_at_batched(&mut self, batch: &[(u64, &[u8])]) -> Result<usize> {
        let offset = self.offset;
        self.disk_op(
            DiskOpKind::Write,
            batch.iter().map(|(block, buf)| (*block * 8 + offset, *buf)),
            |buf, cmd_buf| cmd_buf.copy_from_slice(buf),
            |_buf, _cmd_buf| {},
        )
    }

    fn size(&mut self) -> Result<u64> {
        Ok(self.disk_size)
    }
}

impl Drop for DiskRing {
    fn drop(&mut self) {
        unsafe {
            let _ = libredox::call::munmap(self.shm_base.cast(), POOL_SIZE as usize);
        }
    }
}
