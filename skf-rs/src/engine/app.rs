use crate::engine::crypto::ManagedKeyImpl;
use crate::engine::symbol::{ModApp, ModContainer};
use crate::error::{SkfErr, SkfPinVerifyError};
use crate::helper::{mem, param};
use crate::{
    AppSecurity, ContainerManager, EnvelopedKeyData, Error, FileAttr, FileAttrBuilder, FileManager,
    ManagedKey, PinInfo, SkfApp, SkfContainer, FILE_PERM_NONE,
};
use skf_api::native::error::{SAR_OK, SAR_PIN_INCORRECT};
use skf_api::native::types::{
    ECCCipherBlob, ECCPrivateKeyBlob, ECCPublicKeyBlob, ECCSignatureBlob, EnvelopedKeyBlob,
    FileAttribute, BOOL, BYTE, CHAR, FALSE, HANDLE, LPSTR, TRUE, ULONG,
};
use std::fmt::Debug;
use std::sync::Arc;
use tracing::{instrument, trace};

pub(crate) struct SkfAppImpl {
    lib: Arc<libloading::Library>,
    symbols: ModApp,
    handle: HANDLE,
}

impl SkfAppImpl {
    /// Initialize
    ///
    /// [handle] - The application handle
    ///
    /// [lib] - The library handle
    pub fn new(handle: HANDLE, lib: &Arc<libloading::Library>) -> crate::Result<Self> {
        let lc = Arc::clone(lib);
        let symbols = ModApp::load_symbols(lib)?;
        Ok(Self {
            lib: lc,
            symbols,
            handle,
        })
    }

    pub fn close(&mut self) -> crate::Result<()> {
        if let Some(ref func) = self.symbols.app_close {
            let ret = unsafe { func(self.handle) };
            trace!("[SKF_CloseApplication]: ret = {}", ret);
            if ret != SAR_OK {
                return Err(Error::Skf(SkfErr::of_code(ret)));
            }
            self.handle = std::ptr::null();
        }
        Ok(())
    }
}

impl Debug for SkfAppImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SkfAppImpl")
    }
}
impl Drop for SkfAppImpl {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
impl AppSecurity for SkfAppImpl {
    #[instrument]
    fn change_pin(&self, pin_type: u8, old_pin: &str, new_pin: &str) -> crate::Result<()> {
        let func = self.symbols.pin_change.as_ref().expect("Symbol not load");
        let old_pin = param::as_cstring("old_pin", old_pin)?;
        let new_pin = param::as_cstring("new_pin", new_pin)?;
        let mut count: ULONG = 0;
        let ret = unsafe {
            func(
                self.handle,
                pin_type as ULONG,
                old_pin.as_ptr() as LPSTR,
                new_pin.as_ptr() as LPSTR,
                &mut count,
            )
        };
        trace!("[SKF_ChangePIN]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(()),
            SAR_PIN_INCORRECT => {
                let source = SkfErr::of_code(ret);
                Err(Error::PinVerifyFail(SkfPinVerifyError::new(
                    count,
                    "old pin incorrect",
                    source,
                )))
            }
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }

    #[instrument]
    fn verify_pin(&self, pin_type: u8, pin: &str) -> crate::Result<()> {
        let func = self.symbols.pin_verify.as_ref().expect("Symbol not load");
        let pin = param::as_cstring("pin", pin)?;
        let mut count: ULONG = 0;
        let ret = unsafe {
            func(
                self.handle,
                pin_type as ULONG,
                pin.as_ptr() as LPSTR,
                &mut count,
            )
        };
        trace!("[SKF_VerifyPIN]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(()),
            SAR_PIN_INCORRECT => {
                let source = SkfErr::of_code(ret);
                Err(Error::PinVerifyFail(SkfPinVerifyError::new(
                    count,
                    "pin incorrect",
                    source,
                )))
            }
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }

    #[instrument]
    fn pin_info(&self, pin_type: u8) -> crate::Result<PinInfo> {
        let func = self.symbols.pin_get_info.as_ref().expect("Symbol not load");

        let mut max_retry_count: ULONG = 0;
        let mut remain_retry_count: ULONG = 0;
        let mut default_pin: BOOL = FALSE;

        let ret = unsafe {
            func(
                self.handle,
                pin_type as ULONG,
                &mut max_retry_count,
                &mut remain_retry_count,
                &mut default_pin,
            )
        };
        trace!("[SKF_GetPINInfo]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(PinInfo {
                max_retry_count,
                remain_retry_count,
                default_pin: default_pin != FALSE,
            }),
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }

    #[instrument]
    fn unblock_pin(&self, admin_pin: &str, new_pin: &str) -> crate::Result<()> {
        let func = self.symbols.pin_unblock.as_ref().expect("Symbol not load");
        let admin_pin = param::as_cstring("admin_pin", admin_pin)?;
        let new_pin = param::as_cstring("new_pin", new_pin)?;
        let mut count: ULONG = 0;
        let ret = unsafe {
            func(
                self.handle,
                admin_pin.as_ptr() as LPSTR,
                new_pin.as_ptr() as LPSTR,
                &mut count,
            )
        };
        trace!("[SKF_UnblockPIN]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(()),
            SAR_PIN_INCORRECT => {
                let source = SkfErr::of_code(ret);
                Err(Error::PinVerifyFail(SkfPinVerifyError::new(
                    count,
                    "admin pin incorrect",
                    source,
                )))
            }
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }

    #[instrument]
    fn clear_secure_state(&self) -> crate::Result<()> {
        let func = self
            .symbols
            .app_clear_secure_state
            .as_ref()
            .expect("Symbol not load");
        let ret = unsafe { func(self.handle) };
        trace!("[SKF_ClearSecureState]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(()),
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }
}

impl FileManager for SkfAppImpl {
    #[instrument]
    fn enumerate_file_name(&self) -> crate::Result<Vec<String>> {
        let func = self
            .symbols
            .file_get_list
            .as_ref()
            .expect("Symbol not load");
        let mut len: ULONG = 0;
        let ret = unsafe { func(self.handle, std::ptr::null_mut(), &mut len) };
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        trace!("[SKF_EnumFiles]: desired len = {}", len);
        let mut buff = Vec::<CHAR>::with_capacity(len as usize);
        let ret = unsafe { func(self.handle, buff.as_mut_ptr(), &mut len) };
        trace!("[SKF_EnumFiles]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        unsafe { buff.set_len(len as usize) };
        trace!(
            "[SKF_EnumFiles]: file list = {}",
            String::from_utf8_lossy(&buff)
        );
        // The spec says string list end with two '\0',but vendor may not do it
        let list = unsafe { mem::parse_cstr_list_lossy(buff.as_ptr() as *const u8, buff.len()) };
        Ok(list)
    }

    #[instrument]
    fn create_file(&self, attr: &FileAttr) -> crate::Result<()> {
        let func = self.symbols.file_create.as_ref().expect("Symbol not load");
        let file_name = param::as_cstring("FileAttr.file_name", &attr.file_name)?;
        let ret = unsafe {
            func(
                self.handle,
                file_name.as_ptr() as LPSTR,
                attr.file_size as ULONG,
                attr.read_rights,
                attr.write_rights,
            )
        };
        trace!("[SKF_CreateFile]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(()),
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }

    #[instrument]
    fn delete_file(&self, name: &str) -> crate::Result<()> {
        let func = self.symbols.file_delete.as_ref().expect("Symbol not load");
        let name = param::as_cstring("name", name)?;
        let ret = unsafe { func(self.handle, name.as_ptr() as LPSTR) };
        trace!("[SKF_DeleteFile]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(()),
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }

    #[instrument]
    fn read_file(&self, name: &str, offset: u32, size: usize) -> crate::Result<Vec<u8>> {
        let func = self.symbols.file_read.as_ref().expect("Symbol not load");
        let name = param::as_cstring("name", name)?;
        let mut buff = vec![0u8; size];
        let mut has_read = size as ULONG;
        let ret = unsafe {
            func(
                self.handle,
                name.as_ptr() as LPSTR,
                offset,
                size as ULONG,
                buff.as_mut_ptr() as *mut BYTE,
                &mut has_read,
            )
        };
        trace!("[SKF_ReadFile]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        trace!("[SKF_ReadFile]: len = {}", has_read);
        unsafe { buff.set_len(has_read as usize) };
        Ok(buff)
    }

    #[instrument]
    fn write_file(&self, name: &str, offset: u32, data: &[u8]) -> crate::Result<()> {
        let func = self.symbols.file_write.as_ref().expect("Symbol not load");
        let name = param::as_cstring("name", name)?;
        let ret = unsafe {
            func(
                self.handle,
                name.as_ptr() as LPSTR,
                offset,
                data.as_ptr() as *const BYTE,
                data.len() as ULONG,
            )
        };
        trace!("[SKF_WriteFile]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(()),
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }

    #[instrument]
    fn get_file_info(&self, name: &str) -> crate::Result<FileAttr> {
        let func = self
            .symbols
            .file_get_info
            .as_ref()
            .expect("Symbol not load");
        let name = param::as_cstring("name", name)?;
        let mut attr = FileAttribute::default();
        let ret = unsafe { func(self.handle, name.as_ptr() as LPSTR, &mut attr) };
        trace!("[SKF_GetFileInfo]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(FileAttr::from(&attr)),
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }
}

impl ContainerManager for SkfAppImpl {
    #[instrument]
    fn enumerate_container_name(&self) -> crate::Result<Vec<String>> {
        let func = self
            .symbols
            .container_get_list
            .as_ref()
            .expect("Symbol not load");
        let mut len: ULONG = 0;
        let ret = unsafe { func(self.handle, std::ptr::null_mut(), &mut len) };
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        trace!("[SKF_EnumContainer]: desired len = {}", len);
        let mut buff = Vec::<CHAR>::with_capacity(len as usize);
        let ret = unsafe { func(self.handle, buff.as_mut_ptr(), &mut len) };
        trace!("[SKF_EnumContainer]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        unsafe { buff.set_len(len as usize) };
        trace!(
            "[SKF_EnumContainer]: file list = {}",
            String::from_utf8_lossy(&buff)
        );
        // The spec says string list end with two '\0',but vendor may not do it
        let list = unsafe { mem::parse_cstr_list_lossy(buff.as_ptr(), buff.len()) };
        Ok(list)
    }

    #[instrument]
    fn create_container(&self, name: &str) -> crate::Result<Box<dyn SkfContainer>> {
        let func = self
            .symbols
            .container_create
            .as_ref()
            .expect("Symbol not load");
        let container_name = param::as_cstring("name", name)?;

        let mut handle: HANDLE = std::ptr::null_mut();
        let ret = unsafe { func(self.handle, container_name.as_ptr() as LPSTR, &mut handle) };
        trace!("[SKF_CreateContainer]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(Box::new(SkfContainerImpl::new(handle, &self.lib)?)),
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }

    #[instrument]
    fn open_container(&self, name: &str) -> crate::Result<Box<dyn SkfContainer>> {
        let func = self
            .symbols
            .container_open
            .as_ref()
            .expect("Symbol not load");
        let container_name = param::as_cstring("name", name)?;

        let mut handle: HANDLE = std::ptr::null_mut();
        let ret = unsafe { func(self.handle, container_name.as_ptr() as LPSTR, &mut handle) };
        trace!("[SKF_OpenContainer]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(Box::new(SkfContainerImpl::new(handle, &self.lib)?)),
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }

    #[instrument]
    fn delete_container(&self, name: &str) -> crate::Result<()> {
        let func = self
            .symbols
            .container_delete
            .as_ref()
            .expect("Symbol not load");
        let container_name = param::as_cstring("name", name)?;

        let ret = unsafe { func(self.handle, container_name.as_ptr() as LPSTR) };
        trace!("[SKF_DeleteContainer]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(()),
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }
}

impl SkfApp for SkfAppImpl {}
impl From<&FileAttribute> for FileAttr {
    fn from(value: &FileAttribute) -> Self {
        let file_name: String = unsafe {
            mem::parse_cstr_lossy(value.file_name.as_ptr(), value.file_name.len())
                .unwrap_or("".to_string())
        };
        FileAttr {
            file_name,
            file_size: value.file_size as usize,
            read_rights: value.read_rights,
            write_rights: value.write_rights,
        }
    }
}

impl FileAttr {
    pub fn builder() -> FileAttrBuilder {
        FileAttrBuilder::default()
    }
}

impl Default for FileAttrBuilder {
    fn default() -> Self {
        Self {
            file_name: "".into(),
            file_size: 0,
            read_rights: FILE_PERM_NONE,
            write_rights: FILE_PERM_NONE,
        }
    }
}
impl FileAttrBuilder {
    pub fn file_name(mut self, val: impl Into<String>) -> Self {
        self.file_name = val.into();
        self
    }
    pub fn file_size(mut self, val: usize) -> Self {
        self.file_size = val;
        self
    }
    pub fn read_rights(mut self, val: u32) -> Self {
        self.read_rights = val;
        self
    }
    pub fn write_rights(mut self, val: u32) -> Self {
        self.write_rights = val;
        self
    }
    pub fn build(self) -> FileAttr {
        FileAttr {
            file_name: self.file_name,
            file_size: self.file_size,
            read_rights: self.read_rights,
            write_rights: self.write_rights,
        }
    }
}
pub(crate) struct SkfContainerImpl {
    lib: Arc<libloading::Library>,
    symbols: ModContainer,
    handle: HANDLE,
}

impl SkfContainerImpl {
    /// Initialize
    ///
    /// [handle] - The application handle
    ///
    /// [lib] - The library handle
    pub fn new(handle: HANDLE, lib: &Arc<libloading::Library>) -> crate::Result<Self> {
        let lc = Arc::clone(lib);
        let symbols = ModContainer::load_symbols(lib)?;
        Ok(Self {
            symbols,
            handle,
            lib: lc,
        })
    }

    pub fn close(&mut self) -> crate::Result<()> {
        if let Some(ref func) = self.symbols.ct_close {
            let ret = unsafe { func(self.handle) };
            trace!("[SKF_CloseContainer]: ret = {}", ret);
            if ret != SAR_OK {
                return Err(Error::Skf(SkfErr::of_code(ret)));
            }
            self.handle = std::ptr::null();
        }
        Ok(())
    }
}

impl Debug for SkfContainerImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SkfContainerImpl")
    }
}
impl Drop for SkfContainerImpl {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
impl SkfContainer for SkfContainerImpl {
    #[instrument]
    fn get_type(&self) -> crate::Result<u32> {
        let func = self.symbols.ct_get_type.as_ref().expect("Symbol not load");
        let mut type_value = 0 as ULONG;

        let ret = unsafe { func(self.handle, &mut type_value) };
        trace!("[SKF_GetContainerType]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(type_value as u32),
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }

    #[instrument]
    fn import_certificate(&self, signer: bool, data: &[u8]) -> crate::Result<()> {
        let func = self.symbols.ct_imp_cert.as_ref().expect("Symbol not load");
        let signer = match signer {
            true => TRUE,
            false => FALSE,
        };

        let ret = unsafe {
            func(
                self.handle,
                signer,
                data.as_ptr() as *const BYTE,
                data.len() as ULONG,
            )
        };
        trace!("[SKF_ImportCertificate]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(()),
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }

    #[instrument]
    fn export_certificate(&self, signer: bool) -> crate::Result<Vec<u8>> {
        let func = self.symbols.ct_exp_cert.as_ref().expect("Symbol not load");
        let signer = match signer {
            true => TRUE,
            false => FALSE,
        };
        let mut len: ULONG = 0;
        let ret = unsafe { func(self.handle, signer, std::ptr::null_mut(), &mut len) };
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        trace!("[SKF_ExportCertificate]: desired len = {}", len);
        let mut buff = Vec::<CHAR>::with_capacity(len as usize);
        let ret = unsafe { func(self.handle, signer, buff.as_mut_ptr(), &mut len) };
        trace!("[SKF_ExportCertificate]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        unsafe { buff.set_len(len as usize) };
        Ok(buff)
    }

    #[instrument]
    fn ecc_gen_key_pair(&self, alg_id: u32) -> crate::Result<ECCPublicKeyBlob> {
        let func = self
            .symbols
            .ct_ecc_gen_pair
            .as_ref()
            .expect("Symbol not load");
        let mut blob = ECCPublicKeyBlob::default();
        let ret = unsafe { func(self.handle, alg_id, &mut blob) };
        trace!("[SKF_GenECCKeyPair]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(blob),
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }

    #[instrument]
    fn ecc_import_key_pair(&self, enveloped_key: &EnvelopedKeyData) -> crate::Result<()> {
        let func = self
            .symbols
            .ct_ecc_imp_pair
            .as_ref()
            .expect("Symbol not load");
        let raw_bytes = enveloped_key.blob_bytes();
        let ret = unsafe { func(self.handle, raw_bytes.as_ptr() as *const EnvelopedKeyBlob) };
        trace!("[SKF_ImportECCKeyPair]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(()),
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }

    #[instrument]
    fn ecc_export_public_key(&self, sign_part: bool) -> crate::Result<Vec<u8>> {
        let func = self
            .symbols
            .ct_ecc_exp_pub_key
            .as_ref()
            .expect("Symbol not load");
        let mut len: ULONG = 0;
        let ret = unsafe {
            func(
                self.handle,
                sign_part as BOOL,
                std::ptr::null_mut(),
                &mut len,
            )
        };
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        trace!("[SKF_EccExportPublicKey]: desired len = {}", len);
        let mut buff = Vec::<u8>::with_capacity(len as usize);
        let ret = unsafe {
            func(
                self.handle,
                sign_part as BOOL,
                buff.as_mut_ptr() as *mut BYTE,
                &mut len,
            )
        };
        trace!("[SKF_EccExportPublicKey]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        unsafe { buff.set_len(len as usize) };
        Ok(buff)
    }

    #[instrument]
    fn ecc_sign(&self, hash: &[u8]) -> crate::Result<ECCSignatureBlob> {
        let func = self.symbols.ct_ecc_sign.as_ref().expect("Symbol not load");
        let mut blob = ECCSignatureBlob::default();
        let ret = unsafe {
            func(
                self.handle,
                hash.as_ptr() as *const BYTE,
                hash.len() as ULONG,
                &mut blob,
            )
        };
        trace!("[SKF_ECCSignData]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(blob),
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }

    #[instrument]
    fn sk_gen_agreement_data(
        &self,
        alg_id: u32,
        id: &[u8],
    ) -> crate::Result<(ECCPublicKeyBlob, Box<dyn ManagedKey>)> {
        let func = self
            .symbols
            .ct_sk_gen_agreement
            .as_ref()
            .expect("Symbol not load");
        let mut handle: HANDLE = std::ptr::null_mut();
        let mut pub_key = ECCPublicKeyBlob::default();
        let ret = unsafe {
            func(
                self.handle,
                alg_id as ULONG,
                &mut pub_key,
                id.as_ptr() as *const BYTE,
                id.len() as ULONG,
                &mut handle,
            )
        };
        trace!("[SKF_GenerateAgreementDataWithECC]: ret = {}", ret);
        let managed_key = ManagedKeyImpl::try_new(handle, &self.lib)?;
        match ret {
            SAR_OK => Ok((pub_key, Box::new(managed_key))),
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }

    #[instrument]
    fn sk_gen_agreement_data_and_key(
        &self,
        alg_id: u32,
        initiator_key: &ECCPublicKeyBlob,
        initiator_tmp_key: &ECCPublicKeyBlob,
        initiator_id: &[u8],
        responder_id: &[u8],
    ) -> crate::Result<(ECCPublicKeyBlob, Box<dyn ManagedKey>)> {
        let func = self
            .symbols
            .ct_sk_gen_agreement_and_key
            .as_ref()
            .expect("Symbol not load");
        let mut handle: HANDLE = std::ptr::null_mut();
        let mut pub_key = ECCPublicKeyBlob::default();
        let ret = unsafe {
            func(
                self.handle,
                alg_id as ULONG,
                initiator_key,
                initiator_tmp_key,
                &mut pub_key,
                responder_id.as_ptr() as *const BYTE,
                responder_id.len() as ULONG,
                initiator_id.as_ptr() as *const BYTE,
                initiator_id.len() as ULONG,
                &mut handle,
            )
        };
        trace!("[SKF_GenerateAgreementDataAndKeyWithECC]: ret = {}", ret);
        let managed_key = ManagedKeyImpl::try_new(handle, &self.lib)?;
        match ret {
            SAR_OK => Ok((pub_key, Box::new(managed_key))),
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }

    #[instrument]
    fn sk_import(&self, alg_id: u32, key_data: &[u8]) -> crate::Result<Box<dyn ManagedKey>> {
        let func = self.symbols.ct_sk_imp.as_ref().expect("Symbol not load");
        let mut handle: HANDLE = std::ptr::null_mut();
        let ret = unsafe {
            func(
                self.handle,
                alg_id as ULONG,
                key_data.as_ptr() as *const BYTE,
                key_data.len() as ULONG,
                &mut handle,
            )
        };
        trace!("[SKF_ImportSessionKey]: ret = {}", ret);
        let managed_key = ManagedKeyImpl::try_new(handle, &self.lib)?;
        match ret {
            SAR_OK => Ok(Box::new(managed_key)),
            _ => Err(Error::Skf(SkfErr::of_code(ret))),
        }
    }
}
