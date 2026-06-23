use alloc::vec;
use core::ops;

use crate::{BlockLevel, BlockTrait, RECORD_LEVEL};

#[derive(Clone)]
pub struct RecordRaw(pub(crate) Vec<u8>);

unsafe impl BlockTrait for RecordRaw {
    fn empty(level: BlockLevel) -> Option<Self> {
        if level.0 <= RECORD_LEVEL {
            Some(Self(vec![0; level.bytes() as usize]))
        } else {
            None
        }
    }
}

impl ops::Deref for RecordRaw {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl ops::DerefMut for RecordRaw {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

#[test]
fn record_raw_size_test() {
    for level_i in 0..RECORD_LEVEL {
        let level = BlockLevel(level_i);
        assert_eq!(
            RecordRaw::empty(level).unwrap().len(),
            level.bytes() as usize
        );
    }
}
