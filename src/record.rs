use alloc::{boxed::Box, vec};
use core::ops;

use crate::{BlockLevel, BlockTrait, RECORD_LEVEL};

//TODO: this is a box to prevent stack overflows
pub struct RecordRaw(Box<[u8]>);

unsafe impl BlockTrait for RecordRaw {
    fn empty(level: BlockLevel) -> Option<Self> {
        if level.0 <= RECORD_LEVEL {
            Some(Self(vec![0; level.bytes() as usize].into_boxed_slice()))
        } else {
            None
        }
    }
}

impl Clone for RecordRaw {
    fn clone(&self) -> Self {
        Self(self.0.clone())
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
