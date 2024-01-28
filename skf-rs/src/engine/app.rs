use crate::engine::symbol::ModApp;
use crate::error::{SkfErr, SkfPinVerifyError};
use crate::helper::{mem, param};
use crate::{AppSecurity, ContainerManager, Error, FileAttr, FileManager, PinInfo, SkfApp};
use skf_api::native::error::{SAR_OK, SAR_PIN_INCORRECT};
use skf_api::native::types::{FileAttribute, BOOL, BYTE, CHAR, FALSE, HANDLE, LPSTR, ULONG};
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
            let ret = unsafe { func(self.handle.clone()) };
            trace!("[SKF_CloseApplication]: ret = {}", ret);
            if ret != SAR_OK {
                return Err(Error::Skf(SkfErr::with_default_msg(ret)));
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
                self.handle.clone(),
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
                let source = SkfErr::with_default_msg(ret);
                Err(Error::PinVerifyFail(SkfPinVerifyError::new(
                    count,
                    "old pin incorrect",
                    source,
                )))
            }
            _ => Err(Error::Skf(SkfErr::with_default_msg(ret))),
        }
    }

    #[instrument]
    fn verify_pin(&self, pin_type: u8, pin: &str) -> crate::Result<()> {
        let func = self.symbols.pin_verify.as_ref().expect("Symbol not load");
        let pin = param::as_cstring("pin", pin)?;
        let mut count: ULONG = 0;
        let ret = unsafe {
            func(
                self.handle.clone(),
                pin_type as ULONG,
                pin.as_ptr() as LPSTR,
                &mut count,
            )
        };
        trace!("[SKF_VerifyPIN]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(()),
            SAR_PIN_INCORRECT => {
                let source = SkfErr::with_default_msg(ret);
                Err(Error::PinVerifyFail(SkfPinVerifyError::new(
                    count,
                    "pin incorrect",
                    source,
                )))
            }
            _ => Err(Error::Skf(SkfErr::with_default_msg(ret))),
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
                self.handle.clone(),
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
            _ => Err(Error::Skf(SkfErr::with_default_msg(ret))),
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
                self.handle.clone(),
                admin_pin.as_ptr() as LPSTR,
                new_pin.as_ptr() as LPSTR,
                &mut count,
            )
        };
        trace!("[SKF_UnblockPIN]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(()),
            SAR_PIN_INCORRECT => {
                let source = SkfErr::with_default_msg(ret);
                Err(Error::PinVerifyFail(SkfPinVerifyError::new(
                    count,
                    "admin pin incorrect",
                    source,
                )))
            }
            _ => Err(Error::Skf(SkfErr::with_default_msg(ret))),
        }
    }

    #[instrument]
    fn clear_secure_state(&self) -> crate::Result<()> {
        let func = self
            .symbols
            .app_clear_secure_state
            .as_ref()
            .expect("Symbol not load");
        let ret = unsafe { func(self.handle.clone()) };
        trace!("[SKF_ClearSecureState]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(()),
            _ => Err(Error::Skf(SkfErr::with_default_msg(ret))),
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
        let ret = unsafe { func(self.handle.clone(), std::ptr::null_mut(), &mut len) };
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
        }
        let mut buff = Vec::<CHAR>::with_capacity(len as usize);
        let ret = unsafe { func(self.handle.clone(), buff.as_mut_ptr(), &mut len) };
        trace!("[SKF_EnumFiles]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
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

        let mut file_name = [0u8 as CHAR; 32];
        unsafe {
            mem::write_cstr_ptr(
                attr.file_name.as_str(),
                file_name.as_mut_ptr() as *mut u8,
                file_name.len(),
            );
        }

        let ret = unsafe {
            func(
                self.handle.clone(),
                file_name.as_ptr() as LPSTR,
                attr.file_size,
                attr.read_rights,
                attr.write_rights,
            )
        };
        trace!("[SKF_CreateFile]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(()),
            _ => Err(Error::Skf(SkfErr::with_default_msg(ret))),
        }
    }

    #[instrument]
    fn delete_file(&self, name: &str) -> crate::Result<()> {
        let func = self.symbols.file_delete.as_ref().expect("Symbol not load");
        let name = param::as_cstring("name", name)?;
        let ret = unsafe { func(self.handle.clone(), name.as_ptr() as LPSTR) };
        trace!("[SKF_DeleteFile]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(()),
            _ => Err(Error::Skf(SkfErr::with_default_msg(ret))),
        }
    }

    #[instrument]
    fn read_file(&self, name: &str, offset: u32, size: u32) -> crate::Result<Vec<u8>> {
        let func = self.symbols.file_read.as_ref().expect("Symbol not load");
        let name = param::as_cstring("name", name)?;
        let mut buff = vec![0u8; size as usize];
        let mut has_read = size as ULONG;
        let ret = unsafe {
            func(
                self.handle.clone(),
                name.as_ptr() as LPSTR,
                offset,
                size,
                buff.as_mut_ptr() as *mut BYTE,
                &mut has_read,
            )
        };
        trace!("[SKF_ReadFile]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
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
                self.handle.clone(),
                name.as_ptr() as LPSTR,
                offset,
                data.as_ptr() as *const BYTE,
                data.len() as ULONG,
            )
        };
        trace!("[SKF_WriteFile]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(()),
            _ => Err(Error::Skf(SkfErr::with_default_msg(ret))),
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
        let ret = unsafe { func(self.handle.clone(), name.as_ptr() as LPSTR, &mut attr) };
        trace!("[SKF_GetFileInfo]: ret = {}", ret);
        match ret {
            SAR_OK => Ok(FileAttr::from(&attr)),
            _ => Err(Error::Skf(SkfErr::with_default_msg(ret))),
        }
    }
}

impl ContainerManager for SkfAppImpl {
    #[instrument]
    fn enumerate_container_name(&self) -> crate::Result<Vec<String>> {
        todo!()
    }

    #[instrument]
    fn create_container(&self, name: &str) -> crate::Result<Box<dyn SkfApp>> {
        todo!()
    }

    #[instrument]
    fn open_container(&self, name: &str) -> crate::Result<Box<dyn SkfApp>> {
        todo!()
    }

    #[instrument]
    fn delete_container(&self, name: &str) -> crate::Result<()> {
        todo!()
    }
}

impl From<&FileAttribute> for FileAttr {
    fn from(value: &FileAttribute) -> Self {
        let file_name: String = unsafe {
            mem::parse_cstr_lossy(value.file_name.as_ptr() as *const u8, value.file_name.len())
                .unwrap_or("".to_string())
        };
        FileAttr {
            file_name,
            file_size: value.file_size,
            read_rights: value.read_rights,
            write_rights: value.write_rights,
        }
    }
}
