use std::collections::HashMap;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::slice;
use std::sync::Mutex;

use libredox::flag;
use libredox::Fd;
use redox_rings::raw::RingPopError;
use redox_rings::sync::{BlockingConsumer, BlockingProducer, FutexWaitResult, WaitNotify};
use syscall::error::{Error, Result};
use syscall::CallFlags;
use syscall::TimeSpec;
use syscall::EIO;

use super::Disk;
use crate::SIGNATURE;

const POOL_SIZE: usize = 16 * 1024 * 1024; // 16 MB pool
const CHUNK_SIZE: usize = 256 * 1024;
const RING_SIZE: usize = 65536; // 64 KB rings

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum DiskOpcode {
    Read = 0,
    Write = 1,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DiskOpSqe {
    pub block: u64,
    pub id: u64,
    pub buf_offset: u32,
    pub buf_len: u32,
    pub opcode: u8, // 0 = Read, 1 = Write
    pub pad: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DiskOpCqe {
    pub id: u64,
    pub count: u32,
    pub status: u16, // 0 = Success
    pub pad: u16,
}

pub struct ShmAllocator {
    free_offsets: Mutex<Vec<usize>>,
    chunk_size: usize,
    total_size: usize,
}

impl ShmAllocator {
    pub fn new(total_size: usize, chunk_size: usize) -> Self {
        assert!(total_size % chunk_size == 0);

        let num_chunks = total_size / chunk_size;
        let mut offsets = Vec::with_capacity(num_chunks);
        for i in 0..num_chunks {
            offsets.push(i * chunk_size);
        }
        Self {
            free_offsets: Mutex::new(offsets),
            chunk_size,
            total_size,
        }
    }

    pub fn allocate(&self) -> Option<usize> {
        self.free_offsets.lock().unwrap().pop()
    }

    pub fn deallocate(&self, offset: usize) {
        if offset >= self.total_size || offset % self.chunk_size != 0 {
            log::error!("Invalid deallocate offset: {}", offset);
        }
        self.free_offsets.lock().unwrap().push(offset)
    }
}

pub struct DiskRing {
    sq: BlockingProducer<DiskOpSqe>,
    cq: BlockingConsumer<DiskOpCqe>,
    shm_base: *mut u8,
    allocator: ShmAllocator,
    next_id: u64,
    disk_size: u64,
    offset: u64,
    pipe: Pipe,
}

struct Pipe(Fd);

impl WaitNotify for Pipe {
    fn wait_on_tail(&self, expected_tail: u32, deadline_opt: Option<&TimeSpec>) -> FutexWaitResult {
        unimplemented!("notify_on_tail is not implemented for Pipe")
    }
    fn notify_on_tail(&self) {
        let _ = self.0.write(&[0]);
    }
    fn wait_on_head(&self, expected_head: u32, deadline_opt: Option<&TimeSpec>) -> FutexWaitResult {
        unimplemented!("wait_on_head is not implemented for Pipe")
    }
    fn notify_on_head(&self) {
        unimplemented!("notify_on_head is not implemented for Pipe")
    }
}

impl DiskRing {
    pub fn from_fd(df: &File, disk_size: u64) -> Result<Self> {
        let mut fd_buf = [usize::MAX; 4]; // [pool_shm_fd, sq_shm_fd, cq_shm_fd, pipe_fd]
        let fd_bytes = unsafe {
            std::slice::from_raw_parts_mut(
                fd_buf.as_mut_ptr() as *mut u8,
                fd_buf.len() * std::mem::size_of::<usize>(),
            )
        };
        libredox::call::call_ro(
            df.as_raw_fd() as usize,
            fd_bytes,
            CallFlags::FD | CallFlags::FD_UPPER,
            &[],
        )
        .map_err(|_| Error::new(EIO))?;

        let (pool_fd, sq_shm_fd, cq_shm_fd, pipe) = (
            Fd::new(fd_buf[0]),
            Fd::new(fd_buf[1]),
            Fd::new(fd_buf[2]),
            Fd::new(fd_buf[3]),
        );

        let shm_ptr = unsafe {
            libredox::call::mmap(libredox::call::MmapArgs {
                addr: std::ptr::null_mut(),
                length: POOL_SIZE,
                prot: flag::PROT_READ | flag::PROT_WRITE,
                flags: flag::MAP_SHARED,
                fd: pool_fd.raw(),
                offset: 0,
            })
            .map_err(|_| Error::new(EIO))? as *mut u8
        };

        let sq = BlockingProducer::<DiskOpSqe>::from_fd(sq_shm_fd, false, Some(RING_SIZE))
            .map_err(|_| Error::new(EIO))?;
        let cq = BlockingConsumer::<DiskOpCqe>::from_fd(cq_shm_fd, false, Some(RING_SIZE))
            .map_err(|_| Error::new(EIO))?;

        let mut ring = Self {
            sq,
            cq,
            shm_base: shm_ptr,
            allocator: ShmAllocator::new(POOL_SIZE, CHUNK_SIZE),
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
            if let Ok(_) = ring.disk_op(DiskOpcode::Read, start_lba, &mut buf) {
                if &buf[0..8] == SIGNATURE {
                    ring.offset = start_lba;
                    break;
                }
            }
        }

        Ok(ring)
    }

    fn disk_op(&mut self, opcode: DiskOpcode, start_lba: u64, buffer: &mut [u8]) -> Result<usize> {
        let mut total_processed = 0;
        let mut chunks = buffer.chunks_mut(CHUNK_SIZE).enumerate();
        let mut pending = HashMap::new();

        loop {
            if let Some((i, chunk)) = chunks.next() {
                let len = chunk.len();
                let lba = start_lba + (i as u64 * (CHUNK_SIZE as u64 / 512));

                let buf_offset = loop {
                    if let Some(offset) = self.allocator.allocate() {
                        break offset;
                    }
                    match self.cq.pop(None) {
                        Ok(cqe) => {
                            Self::process_cqe(cqe, &mut pending, self.shm_base, &self.allocator)?
                        }
                        Err(e) => return Err(Error::new(EIO)),
                    }
                };

                if matches!(opcode, DiskOpcode::Write) {
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            chunk.as_ptr(),
                            self.shm_base.add(buf_offset),
                            len,
                        );
                    }
                }

                let new_id = self.next_id;
                self.next_id += 1;
                let sqe = DiskOpSqe {
                    opcode: opcode as u8,
                    block: lba,
                    buf_offset: buf_offset as u32,
                    buf_len: len as u32,
                    id: new_id,
                    pad: [0; 7],
                };

                let chunk_ptr = chunk.as_mut_ptr();
                pending.insert(
                    new_id,
                    (
                        buf_offset,
                        matches!(opcode, DiskOpcode::Read),
                        chunk_ptr,
                        len,
                    ),
                );

                loop {
                    match self.sq.inner.try_push_notify(sqe, &self.pipe) {
                        Ok(_) => break,
                        Err(_) => match self.cq.try_pop() {
                            Ok(cqe) => Self::process_cqe(
                                cqe,
                                &mut pending,
                                self.shm_base,
                                &self.allocator,
                            )?,
                            Err(e) => match e {
                                RingPopError::Empty => {}
                                RingPopError::Broken => return Err(e.into()),
                            },
                        },
                    }
                }

                total_processed += len;
            } else {
                break;
            }
        }

        while !pending.is_empty() {
            match self.cq.pop(None) {
                Ok(cqe) => Self::process_cqe(cqe, &mut pending, self.shm_base, &self.allocator)?,
                Err(e) => return Err(Error::new(EIO)),
            }
        }

        Ok(total_processed)
    }

    fn process_cqe(
        cqe: DiskOpCqe,
        pending: &mut HashMap<u64, (usize, bool, *mut u8, usize)>,
        shm_base: *mut u8,
        allocator: &ShmAllocator,
    ) -> Result<()> {
        if let Some((buf_offset, is_read, chunk_ptr, len)) = pending.remove(&cqe.id) {
            if is_read {
                unsafe {
                    std::ptr::copy_nonoverlapping(shm_base.add(buf_offset), chunk_ptr, len);
                }
            }
            allocator.deallocate(buf_offset);
        }
        Ok(())
    }
}

impl Disk for DiskRing {
    unsafe fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        let lba = (block * 8) + self.offset;
        self.disk_op(DiskOpcode::Read, lba, buffer)
    }

    unsafe fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        let lba = (block * 8) + self.offset;
        let ptr = buffer.as_ptr() as *mut u8;
        let mut_slice = slice::from_raw_parts_mut(ptr, buffer.len());
        self.disk_op(DiskOpcode::Write, lba, mut_slice)
    }

    fn size(&mut self) -> Result<u64> {
        Ok(self.disk_size)
    }
}
