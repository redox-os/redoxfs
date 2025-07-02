use aes::{Aes128, BlockDecrypt, BlockEncrypt, NewBlockCipher};
use xts_mode::Xts128;

// The raw key, keep secret!
#[repr(transparent)]
pub struct Key([u8; 16]);

impl Key {
    /// Generate a random key
    #[cfg(feature = "std")]
    pub fn new() -> Result<Self, getrandom::Error> {
        let mut bytes = [0; 16];
        getrandom::getrandom(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn encrypt(&self, password_aes: &Aes128) -> EncryptedKey {
        let mut block = aes::Block::from(self.0);
        password_aes.encrypt_block(&mut block);
        EncryptedKey(block.into())
    }

    pub fn into_aes(self) -> Aes128 {
        Aes128::new(&aes::Block::from(self.0))
    }
}

/// The encrypted key, encrypted with AES using the salt and password
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct EncryptedKey([u8; 16]);

impl EncryptedKey {
    pub fn decrypt(&self, password_aes: &Aes128) -> Key {
        let mut block = aes::Block::from(self.0);
        password_aes.decrypt_block(&mut block);
        Key(block.into())
    }
}

/// Salt used to prevent rainbow table attacks on the encryption password
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct Salt([u8; 16]);

impl Salt {
    /// Generate a random salt
    #[cfg(feature = "std")]
    pub fn new() -> Result<Self, getrandom::Error> {
        let mut bytes = [0; 16];
        getrandom::getrandom(&mut bytes)?;
        Ok(Self(bytes))
    }
}

/// The key slot, containing the salt and encrypted key that are used with one password
#[derive(Clone, Copy, Default)]
#[repr(C, packed)]
pub struct KeySlot {
    salt: Salt,
    // Two keys for AES XTS 128
    encrypted_keys: (EncryptedKey, EncryptedKey),
}

impl KeySlot {
    /// Get the password AES key (generated from the password and salt, encrypts the real key)
    pub fn password_aes(password: &[u8], salt: &Salt) -> Result<Aes128, argon2::Error> {
        let mut key = Key([0; 16]);

        let mut params_builder = argon2::ParamsBuilder::new();
        params_builder.output_len(key.0.len())?;

        let argon2 = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params_builder.params()?,
        );

        argon2.hash_password_into(password, &salt.0, &mut key.0)?;

        Ok(key.into_aes())
    }

    /// Create a new key slot from a password, salt, and encryption key
    pub fn new(password: &[u8], salt: Salt, keys: (Key, Key)) -> Result<Self, argon2::Error> {
        let password_aes = Self::password_aes(password, &salt)?;
        Ok(Self {
            salt,
            encrypted_keys: (keys.0.encrypt(&password_aes), keys.1.encrypt(&password_aes)),
        })
    }

    /// Get the encryption cipher from this key slot
    pub fn cipher(&self, password: &[u8]) -> Result<Xts128<Aes128>, argon2::Error> {
        let password_aes = Self::password_aes(password, &self.salt)?;
        Ok(Xts128::new(
            self.encrypted_keys.0.decrypt(&password_aes).into_aes(),
            self.encrypted_keys.1.decrypt(&password_aes).into_aes(),
        ))
    }
}
