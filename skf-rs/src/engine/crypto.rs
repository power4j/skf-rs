use crate::engine::symbol::{crypto_fn, ModCrypto, SymbolBundle};
use crate::error::{InvalidArgumentError, SkfErr};
use crate::{BlockCipherParameter, Error, ManagedKey, Result, SkfCrypto};
use skf_api::native::error::SAR_OK;
use skf_api::native::types::{BlockCipherParam, BYTE, HANDLE, MAX_IV_LEN, ULONG};
use std::fmt::Debug;
use std::sync::Arc;
use tracing::{instrument, trace};

pub(crate) struct ManagedKeyImpl {
    close_fn: crypto_fn::SKF_CloseHandle,
    handle: HANDLE,
}
impl Debug for ManagedKeyImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ManagedKeyImpl")
    }
}
impl Drop for ManagedKeyImpl {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl AsRef<HANDLE> for ManagedKeyImpl {
    fn as_ref(&self) -> &HANDLE {
        &self.handle
    }
}

impl ManagedKey for ManagedKeyImpl {}

impl ManagedKeyImpl {
    pub(crate) fn try_new(handle: HANDLE, lib: &Arc<libloading::Library>) -> Result<Self> {
        let close_fn = unsafe { SymbolBundle::new(lib, b"SKF_CloseHandle\0")? };
        Ok(Self { close_fn, handle })
    }

    #[instrument]
    pub(crate) fn close(&self) -> Result<()> {
        let ret = unsafe { (self.close_fn)(self.handle.clone()) };
        trace!("[SKF_CloseHandle]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        Ok(())
    }
}

pub(crate) struct SkfCryptoImpl {
    symbols: ModCrypto,
}
impl Debug for SkfCryptoImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SkfCryptoImpl")
    }
}
impl SkfCryptoImpl {
    pub fn new(lib: &Arc<libloading::Library>) -> Result<Self> {
        let symbols = ModCrypto::load_symbols(lib)?;
        Ok(Self { symbols })
    }
}

impl SkfCrypto for SkfCryptoImpl {
    #[instrument(skip(key))]
    fn encrypt_init(&self, key: &dyn ManagedKey, param: &BlockCipherParameter) -> Result<()> {
        let func = self.symbols.encrypt_init.as_ref().expect("Symbol not load");
        let param = make_cipher_param(param)?;
        let ret = unsafe { func(key.as_ref().clone(), param) };
        trace!("[SKF_EncryptInit]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        Ok(())
    }

    #[instrument(skip(key))]
    fn encrypt(&self, key: &dyn ManagedKey, data: &[u8], buffer_size: usize) -> Result<Vec<u8>> {
        let func = self.symbols.encrypt.as_ref().expect("Symbol not load");
        let mut len = buffer_size as ULONG;
        let mut buffer = Vec::<u8>::with_capacity(buffer_size);
        let ret = unsafe {
            func(
                key.as_ref().clone(),
                data.as_ptr() as *const BYTE,
                data.len() as ULONG,
                buffer.as_mut_ptr() as *mut BYTE,
                &mut len,
            )
        };
        trace!("[SKF_Encrypt]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        trace!("[SKF_Encrypt]: output len = {}", len);
        unsafe { buffer.set_len(len as usize) };
        Ok(buffer)
    }

    #[instrument(skip(key))]
    fn decrypt_init(&self, key: &dyn ManagedKey, param: &BlockCipherParameter) -> Result<()> {
        todo!()
    }

    #[instrument(skip(key))]
    fn decrypt(&self, key: &dyn ManagedKey, data: &[u8], buffer_size: usize) -> Result<Vec<u8>> {
        todo!()
    }
}

fn make_cipher_param(src: &BlockCipherParameter) -> Result<BlockCipherParam> {
    if src.iv.len() > MAX_IV_LEN {
        let err = InvalidArgumentError::new(format!("max iv length is {}", MAX_IV_LEN), None);
        return Err(Error::InvalidArgument(err));
    }
    let mut iv = [0u8 as BYTE; MAX_IV_LEN];
    unsafe { std::ptr::copy(src.iv.as_ptr(), iv.as_mut_ptr(), src.iv.len()) };
    Ok(BlockCipherParam {
        iv,
        iv_len: src.iv.len() as ULONG,
        padding_type: src.padding_type as ULONG,
        feed_bit_len: src.feed_bit_len as ULONG,
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn make_cipher_param_test() {
        let src = BlockCipherParameter {
            iv: vec![],
            padding_type: 0,
            feed_bit_len: 0,
        };
        assert!(make_cipher_param(&src).is_ok());

        let src = BlockCipherParameter {
            iv: [0u8; 1].to_vec(),
            padding_type: 0,
            feed_bit_len: 0,
        };
        assert!(make_cipher_param(&src).is_ok());

        // fail case: iv length > 32
        let src = BlockCipherParameter {
            iv: [0u8; 33].to_vec(),
            padding_type: 0,
            feed_bit_len: 0,
        };
        assert!(matches!(
            make_cipher_param(&src).unwrap_err(),
            Error::InvalidArgument(_)
        ));
    }
}
