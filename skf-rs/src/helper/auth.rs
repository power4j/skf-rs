use crate::error::InvalidArgumentError;
use crate::spec::algorithm;
use crate::{BlockCipherParameter, Error, Result, SkfDevice};

/// Get pcks7 aligned length
///
/// [len] - The data length
///
/// [block_size] - The block size of the algorithm
#[inline]
pub fn pcks7_aligned_len(len: usize, block_size: usize) -> usize {
    len + (block_size - (len % block_size))
}

/// Encrypt device auth key, using sm1 ecb
///
/// [device] - The device instance
///
/// [key] - The auth key to encrypt, 16 bytes
pub fn encrypt_auth_key_sm1_ecb(device: &dyn SkfDevice, key: &[u8]) -> Result<Vec<u8>> {
    let block_size: usize = 16;
    if key.len() != block_size {
        let msg = format!("key length should be {}", block_size);
        return Err(Error::InvalidArgument(InvalidArgumentError::new(msg, None)));
    }
    let key_handle = device.set_symmetric_key(algorithm::SGD_SM1_ECB, key)?;
    let crypto = device.block_cipher()?;
    let mut data = device.gen_random(8)?;
    if data.len() < block_size {
        data.extend(std::iter::repeat(0).take(block_size - data.len()));
    }
    let param = BlockCipherParameter {
        iv: vec![],
        padding_type: 1,
        feed_bit_len: 0,
    };
    let buff_size = pcks7_aligned_len(data.len(), block_size);
    let _ = crypto.encrypt_init(key_handle.as_ref(), &param)?;
    crypto.encrypt(key_handle.as_ref(), &data, buff_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcks7_aligned_len_test() {
        assert_eq!(pcks7_aligned_len(0, 16), 16);
        assert_eq!(pcks7_aligned_len(15, 16), 16);
        assert_eq!(pcks7_aligned_len(16, 16), 32);
        assert_eq!(pcks7_aligned_len(17, 16), 32);
    }
}
