use crate::engine::app::SkfAppImpl;
use crate::engine::crypto;
use crate::engine::crypto::ManagedKeyImpl;
use crate::engine::symbol::ModDev;
use crate::error::SkfErr;
use crate::helper::{mem, param};
use crate::{
    AppAttr, AppManager, DeviceAuth, DeviceCrypto, DeviceCtl, DeviceInformation, ECCEncryptedData,
    ECCPrivateKeyBlob, ECCPublicKeyBlob, ECCSignatureBlob, ManagedKey, SkfApp, SkfBlockCipher,
    SkfDevice, Version,
};
use crate::{Error, Result};
use skf_api::native::error::SAR_OK;
use skf_api::native::types::{
    DeviceInfo, ECCCipherBlob, BYTE, CHAR, DEV_LOCK_FOREVER, DWORD, HANDLE, LPSTR, ULONG,
};
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use tracing::{instrument, trace};

pub(crate) struct SkfDeviceImpl {
    lib: Arc<libloading::Library>,
    symbols: ModDev,
    handle: HANDLE,
    name: String,
}

impl SkfDeviceImpl {
    /// Initialize
    ///
    /// [handle] - Native handle
    ///
    /// [lib] - The library handle
    pub fn new(handle: HANDLE, name: &str, lib: &Arc<libloading::Library>) -> Result<Self> {
        let lc = Arc::clone(lib);
        let symbols = ModDev::load_symbols(lib)?;
        Ok(Self {
            lib: lc,
            symbols,
            handle,
            name: name.to_string(),
        })
    }

    #[instrument]
    fn disconnect(&mut self) -> Result<()> {
        if let Some(ref func) = self.symbols.dev_dis_connect {
            let ret = unsafe { func(self.handle) };
            trace!("[SKF_DisConnectDev]: ret = {}", ret);
            if ret != SAR_OK {
                return Err(Error::Skf(SkfErr::of_code(ret)));
            }
            self.handle = std::ptr::null();
        }
        Ok(())
    }
}

impl Debug for SkfDeviceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SkfDeviceImpl({})", &self.name)
    }
}

impl DeviceAuth for SkfDeviceImpl {
    #[instrument(skip(data))]
    fn device_auth(&self, data: &[u8]) -> Result<()> {
        let func = self.symbols.dev_auth.as_ref().expect("Symbol not load");
        let ret = unsafe {
            func(
                self.handle,
                data.as_ptr() as *const BYTE,
                data.len() as ULONG,
            )
        };
        trace!("[SKF_DevAuth]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        Ok(())
    }

    #[instrument(skip(key))]
    fn change_device_auth_key(&self, key: &[u8]) -> Result<()> {
        let func = self
            .symbols
            .dev_change_auth_key
            .as_ref()
            .expect("Symbol not load");
        let ret = unsafe { func(self.handle, key.as_ptr() as *const BYTE, key.len() as ULONG) };
        trace!("[SKF_ChangeDevAuthKey]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        Ok(())
    }
}

impl DeviceCtl for SkfDeviceImpl {
    #[instrument]
    fn set_label(&self, label: &str) -> Result<()> {
        let func = self
            .symbols
            .dev_set_label
            .as_ref()
            .expect("Symbol not load");
        let label = param::as_cstring("label", label)?;
        let ret = unsafe { func(self.handle, label.as_ptr() as *const CHAR) };
        trace!("[SKF_SetLabel]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        Ok(())
    }

    #[instrument]
    fn info(&self) -> Result<DeviceInformation> {
        let func = self.symbols.dev_get_info.as_ref().expect("Symbol not load");
        let mut data = DeviceInfo::default();
        let ret = unsafe { func(self.handle, &mut data) };
        trace!("[SKF_GetDevInfo]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        Ok(DeviceInformation::from(&data))
    }

    #[instrument]
    fn lock(&self, timeout: Option<Duration>) -> Result<()> {
        let func = self.symbols.dev_lock.as_ref().expect("Symbol not load");
        let timeout = timeout
            .map(|ref v| v.as_millis() as ULONG)
            .unwrap_or(DEV_LOCK_FOREVER);
        let ret = unsafe { func(self.handle, timeout) };
        trace!("[SKF_LockDev]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        Ok(())
    }

    #[instrument]
    fn unlock(&self) -> Result<()> {
        let func = self.symbols.dev_unlock.as_ref().expect("Symbol not load");
        let ret = unsafe { func(self.handle) };
        trace!("[SKF_UnlockDev]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        Ok(())
    }
    #[instrument]
    fn transmit(&self, command: &[u8], recv_capacity: usize) -> Result<Vec<u8>> {
        let func = self.symbols.dev_transmit.as_ref().expect("Symbol not load");
        let mut len: ULONG = recv_capacity as ULONG;
        let mut buffer = Vec::<u8>::with_capacity(recv_capacity);
        let ret = unsafe {
            func(
                self.handle,
                command.as_ptr() as *const BYTE,
                command.len() as ULONG,
                buffer.as_mut_ptr() as *mut BYTE,
                &mut len,
            )
        };
        trace!("[SKF_Transmit]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        trace!("[SKF_Transmit]: output len = {}", len);
        unsafe { buffer.set_len(len as usize) };
        Ok(buffer)
    }
}

impl DeviceCrypto for SkfDeviceImpl {
    #[instrument]
    fn gen_random(&self, len: usize) -> Result<Vec<u8>> {
        let func = self.symbols.gen_random.as_ref().expect("Symbol not load");
        let mut buffer = Vec::<u8>::with_capacity(len);
        let ret = unsafe { func(self.handle, buffer.as_mut_ptr() as *mut BYTE, len as ULONG) };
        trace!("[SKF_GenRandom]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        unsafe { buffer.set_len(len) };
        Ok(buffer)
    }

    #[instrument(skip(key))]
    fn set_symmetric_key(&self, alg_id: u32, key: &[u8]) -> Result<Box<dyn ManagedKey>> {
        let func = self
            .symbols
            .sym_key_import
            .as_ref()
            .expect("Symbol not load");
        let mut handle: HANDLE = std::ptr::null_mut();
        let ret = unsafe {
            func(
                self.handle,
                key.as_ptr() as *const BYTE,
                alg_id,
                &mut handle,
            )
        };
        trace!("[SKF_SetSymmKey]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        let managed_key = ManagedKeyImpl::try_new(handle, &self.lib)?;
        Ok(Box::new(managed_key))
    }

    #[instrument(skip(key, data))]
    fn ext_ecc_encrypt(&self, key: &ECCPublicKeyBlob, data: &[u8]) -> Result<ECCEncryptedData> {
        let func = self
            .symbols
            .ecc_ext_encrypt
            .as_ref()
            .expect("Symbol not load");
        let buff_size = ECCCipherBlob::size_of(data.len());
        let mut buff: Vec<u8> = vec![0; buff_size];

        let ret = unsafe {
            func(
                self.handle,
                key as *const ECCPublicKeyBlob,
                data.as_ptr() as *const BYTE,
                data.len() as ULONG,
                buff.as_mut_ptr() as *mut ECCCipherBlob,
            )
        };
        trace!("[SKF_ExtECCEncrypt]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        let blob = unsafe {
            let cb = &*(buff.as_ptr() as *const ECCCipherBlob);
            let mut cipher: Vec<u8> = vec![];
            if cb.cipher_len > 0 {
                let len = cb.cipher_len as usize;
                cipher = vec![0; len];
                std::ptr::copy(cb.cipher.as_ptr(), cipher.as_mut_ptr(), len);
            }
            ECCEncryptedData {
                ec_x: cb.x_coordinate,
                ec_y: cb.y_coordinate,
                hash: cb.hash,
                cipher,
            }
        };
        Ok(blob)
    }

    #[instrument(skip(key, cipher))]
    fn ext_ecc_decrypt(
        &self,
        key: &ECCPrivateKeyBlob,
        cipher: &ECCEncryptedData,
    ) -> Result<Vec<u8>> {
        let func = self
            .symbols
            .ecc_ext_decrypt
            .as_ref()
            .expect("Symbol not load");
        let cipher_mem = cipher.blob_bytes();
        let mut buff: Vec<u8> = Vec::with_capacity(cipher.cipher.len());
        let mut buff_len: ULONG = buff.len() as ULONG;

        let ret = unsafe {
            func(
                self.handle,
                key as *const ECCPrivateKeyBlob,
                cipher_mem.as_ptr() as *const ECCCipherBlob,
                buff.as_mut_ptr() as *mut BYTE,
                &mut buff_len,
            )
        };
        trace!("[SKF_ExtECCDecrypt]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }

        trace!("[SKF_ExtECCDecrypt]: len = {}", buff_len);
        unsafe { buff.set_len(buff_len as usize) };

        Ok(buff)
    }

    #[instrument(skip(key, data))]
    fn ext_ecc_sign(&self, key: &ECCPrivateKeyBlob, data: &[u8]) -> Result<ECCSignatureBlob> {
        let func = self.symbols.ecc_ext_sign.as_ref().expect("Symbol not load");

        let mut sign = ECCSignatureBlob::default();
        let ret = unsafe {
            func(
                self.handle,
                key as *const ECCPrivateKeyBlob,
                data.as_ptr() as *const BYTE,
                data.len() as ULONG,
                &mut sign,
            )
        };
        trace!("[SKF_ExtECCSign]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }

        Ok(sign)
    }

    #[instrument(skip(key, data, signature))]
    fn ext_ecc_verify(
        &self,
        key: &ECCPublicKeyBlob,
        data: &[u8],
        signature: &ECCSignatureBlob,
    ) -> Result<()> {
        let func = self
            .symbols
            .ecc_ext_verify
            .as_ref()
            .expect("Symbol not load");

        let ret = unsafe {
            func(
                self.handle,
                key as *const ECCPublicKeyBlob,
                data.as_ptr() as *const BYTE,
                data.len() as ULONG,
                signature as *const ECCSignatureBlob,
            )
        };
        trace!("[SKF_ExtECCVerify]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        Ok(())
    }

    #[instrument(skip(key, hash, signature))]
    fn ecc_verify(
        &self,
        key: &ECCPublicKeyBlob,
        hash: &[u8],
        signature: &ECCSignatureBlob,
    ) -> Result<()> {
        let func = self.symbols.ecc_verify.as_ref().expect("Symbol not load");

        let ret = unsafe {
            func(
                self.handle,
                key as *const ECCPublicKeyBlob,
                hash.as_ptr() as *const BYTE,
                hash.len() as ULONG,
                signature as *const ECCSignatureBlob,
            )
        };
        trace!("[SKF_ECCVerify]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        Ok(())
    }

    #[instrument(skip(agreement_key, responder_key, responder_tmp_key, responder_id))]
    fn ecc_gen_session_key(
        &self,
        agreement_key: &dyn ManagedKey,
        responder_key: &ECCPublicKeyBlob,
        responder_tmp_key: &ECCPublicKeyBlob,
        responder_id: &[u8],
    ) -> Result<Box<dyn ManagedKey>> {
        let func = self.symbols.ecc_gen_sk.as_ref().expect("Symbol not load");

        let mut handle: HANDLE = std::ptr::null_mut();
        let ret = unsafe {
            func(
                *agreement_key.as_ref(),
                responder_key,
                responder_tmp_key,
                responder_id.as_ptr() as *const BYTE,
                responder_id.len() as ULONG,
                &mut handle,
            )
        };
        trace!("[SKF_GenerateKeyWithECC]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        let managed_key = ManagedKeyImpl::try_new(handle, &self.lib)?;
        Ok(Box::new(managed_key))
    }
}
impl AppManager for SkfDeviceImpl {
    #[instrument]
    fn enumerate_app_name(&self) -> Result<Vec<String>> {
        let func = self.symbols.app_enum.as_ref().expect("Symbol not load");
        let mut len: ULONG = 0;
        let ret = unsafe { func(self.handle, std::ptr::null_mut(), &mut len) };
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        trace!("[SKF_EnumApplication]: desired len = {}", len);
        if len == 0 {
            return Ok(vec![]);
        }
        let mut buff = Vec::<CHAR>::with_capacity(len as usize);
        let ret = unsafe { func(self.handle, buff.as_mut_ptr(), &mut len) };
        trace!("[SKF_EnumApplication]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        unsafe { buff.set_len(len as usize) };
        trace!(
            "[SKF_EnumApplication]: app list = {}",
            String::from_utf8_lossy(&buff)
        );
        // The spec says string list end with two '\0',but vendor may not do it
        let list = unsafe { mem::parse_cstr_list_lossy(buff.as_ptr(), buff.len()) };
        Ok(list)
    }

    #[instrument]
    fn create_app(&self, name: &str, attr: &AppAttr) -> Result<Box<dyn SkfApp>> {
        let func = self.symbols.app_create.as_ref().expect("Symbol not load");
        let c_name = param::as_cstring("name", name)?;
        let admin_pin = param::as_cstring("AppAttr.admin_pin", &attr.admin_pin)?;
        let user_pin = param::as_cstring("AppAttr.user_pin", &attr.user_pin)?;
        let mut handle: HANDLE = std::ptr::null_mut();
        let ret = unsafe {
            func(
                self.handle,
                c_name.as_ptr() as *const CHAR,
                admin_pin.as_ptr() as *const CHAR,
                attr.admin_pin_retry_count as DWORD,
                user_pin.as_ptr() as *const CHAR,
                attr.user_pin_retry_count as DWORD,
                attr.create_file_rights as DWORD,
                &mut handle,
            )
        };
        trace!("[SKF_CreateApplication]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        let app = SkfAppImpl::new(handle, name, &self.lib)?;
        Ok(Box::new(app))
    }

    #[instrument]
    fn open_app(&self, name: &str) -> Result<Box<dyn SkfApp>> {
        let func = self.symbols.app_open.as_ref().expect("Symbol not load");
        let c_name = param::as_cstring("name", name)?;
        let mut handle: HANDLE = std::ptr::null_mut();
        let ret = unsafe { func(self.handle, c_name.as_ptr() as LPSTR, &mut handle) };
        trace!("[SKF_OpenApplication]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        let app = SkfAppImpl::new(handle, name, &self.lib)?;
        Ok(Box::new(app))
    }

    #[instrument]
    fn delete_app(&self, name: &str) -> Result<()> {
        let func = self.symbols.app_delete.as_ref().expect("Symbol not load");
        let name = param::as_cstring("name", name)?;
        let ret = unsafe { func(self.handle, name.as_ptr() as LPSTR) };
        trace!("[SKF_DeleteApplication]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        Ok(())
    }
}

impl SkfDevice for SkfDeviceImpl {
    fn block_cipher(&self) -> Result<Box<dyn SkfBlockCipher + Send + Sync>> {
        let crypto = crypto::SkfBlockCipherImpl::new(&self.lib)?;
        Ok(Box::new(crypto))
    }

    fn name(&self) -> &str {
        &self.name
    }
}
impl Drop for SkfDeviceImpl {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}

impl From<&DeviceInfo> for DeviceInformation {
    fn from(value: &DeviceInfo) -> Self {
        let version = Version {
            major: value.version.major,
            minor: value.version.minor,
        };
        let manufacturer: String = unsafe {
            mem::parse_cstr_lossy(value.manufacturer.as_ptr(), value.manufacturer.len())
                .unwrap_or("".to_string())
        };
        let issuer: String = unsafe {
            mem::parse_cstr_lossy(value.issuer.as_ptr(), value.issuer.len())
                .unwrap_or("".to_string())
        };
        let label: String = unsafe {
            mem::parse_cstr_lossy(value.label.as_ptr(), value.label.len()).unwrap_or("".to_string())
        };
        let serial_number = unsafe {
            mem::parse_cstr_lossy(value.serial_number.as_ptr(), value.serial_number.len())
                .unwrap_or("".to_string())
        };
        let hw_version = Version {
            major: value.hw_version.major,
            minor: value.hw_version.minor,
        };
        let firmware_version = Version {
            major: value.firmware_version.major,
            minor: value.firmware_version.minor,
        };
        let alg_sym_cap = value.alg_sym_cap;
        let alg_asym_cap = value.alg_asym_cap;
        let alg_hash_cap = value.alg_hash_cap;
        let dev_auth_alg_id = value.dev_auth_alg_id;
        let total_space = value.total_space;
        let free_space = value.free_space;
        let max_ecc_buffer_size = value.max_ecc_buffer_size;
        let max_buffer_size = value.max_buffer_size;
        let reserved = value.reserved;
        Self {
            version,
            manufacturer,
            issuer,
            label,
            serial_number,
            hw_version,
            firmware_version,
            alg_sym_cap,
            alg_asym_cap,
            alg_hash_cap,
            dev_auth_alg_id,
            total_space,
            free_space,
            max_ecc_buffer_size,
            max_buffer_size,
            reserved,
        }
    }
}
