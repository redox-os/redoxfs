use std::str;
use std::ops;
use std::mem;

#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Copy, Clone)]
pub enum FileNameError {
    NotUtf8,
    ZeroSized,
    TooLong,
    ForbiddenCharacter
}

const MAX_FILENAME : usize = 220;

/// FileNameBuf size
/// Based on maximum length of filename in bytes + 1 byte to contain
/// filename length + 1 byte NUL as sentinel
const FILENAMEBUF_SIZE : usize = MAX_FILENAME + 1 + 1;

/// Contain valid filename/foldername inside redoxfs
/// Invariants is:
/// - Utf8
/// - Don't have '\0', '/'
/// - minimum filename length is 1
/// - maximum filename length is MAX_FILENAME
/// - using '\0' as sentinel
/// - index zero in self.inner is filename size in bytes
pub struct FileNameBuf {
    inner: [u8; FILENAMEBUF_SIZE]
}


/// Filename contain RedoxFS valid filename
#[derive(PartialEq, Eq, Debug)]
pub struct FileName {
    inner: [u8]
}


impl Default for FileNameBuf {
    fn default() -> Self {
        // FileName cannot contain empty name, so we defaulted to some name
        let bytes = FileNameBuf::copy_buffer(b"RedoxFS");

        FileNameBuf {
            inner: bytes
        }
    }
}


impl FileNameBuf {
    /// Create instance of FileNameBuf from some byte slice without any check of validity.
    /// Use this function when you are sure that the input is already valid.
    pub unsafe fn from_unchecked_bytes(name: &[u8]) -> FileNameBuf {
        let bytes = Self::copy_buffer(name);

        FileNameBuf {
            inner: bytes
        }
    }

    /// copy source bytes slice to new byte array suitable for FileNameBuf
    fn copy_buffer(source: &[u8]) -> [u8; FILENAMEBUF_SIZE] {
        use std::cmp;

        let mut bytes = [0; FILENAMEBUF_SIZE];
        let len = cmp::min(source.len(), MAX_FILENAME);

        bytes[0] = len as u8;
        bytes[1 ... len].copy_from_slice(source);
        bytes
    }
}


impl ops::Deref for FileNameBuf {
    type Target = FileName;

    fn deref(&self) -> &FileName {
        FileName::new(&self)
    }
}

impl FileName {
    pub fn new(f: &FileNameBuf) -> &FileName {
        let size = f.inner[0] as usize;
        let slice = &f.inner[1...size];

        unsafe { mem::transmute(slice.as_ref()) }
    }

    pub fn from_str(s: &str) -> Result<&FileName, FileNameError> {
        // string is already UTF8 so we only check other rules
        let _ = Self::check_valid_len(s)?;
        let _ = Self::check_allowed_character(s)?;

        let name = unsafe { mem::transmute(s) };
        Ok(name)
    }

    pub fn from_bytes(name: &[u8]) -> Result<&FileName, FileNameError> {
        let name = match str::from_utf8(name) {
            Ok(name) => name,
            Err(_) => return Err(FileNameError::NotUtf8),
        };

        Self::from_str(name)
    }

    pub fn to_filename_buf(&self) -> FileNameBuf {
        unsafe {
            FileNameBuf::from_unchecked_bytes(&self.inner)
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    pub fn as_str(&self) -> &str {
        /// its okay to use unsafe because we guaranteed that self.inner is always UTF-8
        let s = unsafe { str::from_utf8_unchecked(&self.inner) };
        s
    }

    /// check if s has valid length for filename, return the length of filename
    /// in bytes. otherwise:
    ///  - FileNameError::ZeroSized when empty
    ///  - FileNameError::TooLong when length is too much in RedoxFS
    fn check_valid_len(s: &str) -> Result<u8, FileNameError> {
        match s.len() {
            0 => return Err(FileNameError::ZeroSized),
            x if x > MAX_FILENAME => return Err(FileNameError::TooLong),
            x => Ok(x as u8)
        }
    }

    fn check_allowed_character(s: &str) -> Result<(), FileNameError> {
        for ch in s.bytes() {
            match Self::is_allowed_character(ch) {
                false => return Err(FileNameError::ForbiddenCharacter),
                _ => {}
            }
        }

        Ok(())
    }

    fn is_allowed_character(ch: u8) -> bool {
        // prevent certain character inside filename. for now we only follow
        // UNIX style, just prevent NUL and / character.
        match ch {
            0 | b'/' => false,
            _ => true,
        }
    }

}


#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! assert_filename_ok {
        ($value:expr) => {
            let name = FileName::from_bytes($value);
            assert!(name.is_ok());
        };
    }

    macro_rules! assert_filename_err {
        ($value:expr, $expected:expr) => {
            let name = FileName::from_bytes($value);
            match name {
                Ok(name) => panic!("filename must be error but got valid name with length {}", name.inner.len()),
                Err(why) => assert_eq!(why, $expected),
            };
        };
    }

    #[test]
    fn test_as_str() {
        let name = "foo.bar";
        let redox_name = FileName::from_str(name).unwrap();
        assert_eq!(redox_name.as_str(), name);
    }

    #[test]
    fn test_eq(){
        let name1 = FileName::from_str("foo.txt").unwrap();
        let name2 = FileName::from_str("foo.txt").unwrap();
        let name3 = FileName::from_str("bar.txt").unwrap();

        assert_eq!(name1, name2);
        assert_ne!(name1, name3);
    }

    #[test]
    fn test_allowed_filename() {
        assert_filename_ok!("abcdefghijklmnopqrstuvwxyz".as_bytes());
        assert_filename_ok!("ABCDEFGHIJKLMNOPQRSTUVWXYZ".as_bytes());
        assert_filename_ok!("01234567890".as_bytes());
        assert_filename_ok!(r##"~`!@#$%^&*()_-+=[]{}|,.;"'"##.as_bytes());
        assert_filename_ok!("こんにちは世界".as_bytes());
        assert_filename_ok!("Здравствулте мир".as_bytes());
        assert_filename_ok!("여보세요 세계".as_bytes());
        assert_filename_ok!("你好世界".as_bytes());

        let mut name: [u8; 1] = [0];
        // 47 is '/'
        for i in 1..46 {
            name[0] = i;
            assert_filename_ok!(&name);
        }
        for i in 48..128 {
            name[0] = i;
            assert_filename_ok!(&name);
        }
    }

    #[test]
    fn test_forbidden_filename() {
        assert_filename_err!("embedded NUL(\0) inside filename".as_bytes(), FileNameError::ForbiddenCharacter);
        assert_filename_err!("embedded slash(/) inside filename".as_bytes(), FileNameError::ForbiddenCharacter);
    }

    #[test]
    fn test_forbidden_length() {
        assert_filename_err!(b"", FileNameError::ZeroSized);

        let name: [u8; MAX_FILENAME + 1] = [b'a'; MAX_FILENAME + 1];
        assert_filename_err!(&name, FileNameError::TooLong);
    }
}
