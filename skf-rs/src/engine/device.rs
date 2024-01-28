use crate::engine::symbol::ModDev;
use crate::error::{InvalidArgumentError, SkfErr};
use crate::helper::{mem, param};
use crate::{
    AppManager, CreateAppOption, DeviceCtl, DeviceInformation, DeviceSecurity, SkfApp, SkfDevice,
    Version,
};
use crate::{Error, Result};
use skf_api::native::error::SAR_OK;
use skf_api::native::types::{
    DeviceInfo, BOOL, BYTE, CHAR, DEV_LOCK_FOREVER, DWORD, HANDLE, LPSTR, ULONG,
};
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use tracing::{instrument, trace};

pub(crate) struct SkfDeviceImpl {
    lib: Arc<libloading::Library>,
    symbols: ModDev,
    handle: HANDLE,
}

impl SkfDeviceImpl {
    /// Initialize
    ///
    /// [handle] - Native handle
    ///
    /// [lib] - The library handle
    pub fn new(handle: HANDLE, lib: &Arc<libloading::Library>) -> Result<Self> {
        let lc = Arc::clone(lib);
        let symbols = ModDev::load_symbols(lib)?;
        Ok(Self {
            lib: lc,
            symbols,
            handle,
        })
    }

    fn disconnect(&mut self) -> Result<()> {
        if let Some(ref func) = self.symbols.dev_dis_connect {
            let ret = unsafe { func(self.handle.clone()) };
            trace!("[SKF_DisConnectDev]: ret = {}", ret);
            if ret != SAR_OK {
                return Err(Error::Skf(SkfErr::with_default_msg(ret)));
            }
            self.handle = std::ptr::null();
        }
        Ok(())
    }
}

impl Debug for SkfDeviceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SkfDeviceImpl")
    }
}

impl DeviceSecurity for SkfDeviceImpl {
    #[instrument]
    fn device_auth(&self, data: &[u8]) -> Result<()> {
        let func = self.symbols.dev_auth.as_ref().expect("Symbol not load");
        let ret = unsafe {
            func(
                self.handle.clone(),
                data.as_ptr() as *const BYTE,
                data.len() as ULONG,
            )
        };
        trace!("[SKF_DevAuth]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
        }
        Ok(())
    }

    #[instrument]
    fn change_device_auth_key(&self, key: &[u8]) -> Result<()> {
        let func = self
            .symbols
            .dev_change_auth_key
            .as_ref()
            .expect("Symbol not load");
        let ret = unsafe {
            func(
                self.handle.clone(),
                key.as_ptr() as *const BYTE,
                key.len() as ULONG,
            )
        };
        trace!("[SKF_ChangeDevAuthKey]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
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
        let ret = unsafe { func(self.handle.clone(), label.as_ptr() as *const CHAR) };
        trace!("[SKF_SetLabel]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
        }
        Ok(())
    }

    #[instrument]
    fn info(&self) -> Result<DeviceInformation> {
        let func = self.symbols.dev_get_info.as_ref().expect("Symbol not load");
        let mut data = DeviceInfo::default();
        let ret = unsafe { func(self.handle.clone(), &mut data) };
        trace!("[SKF_GetDevInfo]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
        }
        Ok(DeviceInformation::from(&data))
    }

    #[instrument]
    fn lock(&self, timeout: Option<Duration>) -> Result<()> {
        let func = self.symbols.dev_lock.as_ref().expect("Symbol not load");
        let timeout = timeout
            .map(|ref v| v.as_millis() as ULONG)
            .unwrap_or(DEV_LOCK_FOREVER);
        let ret = unsafe { func(self.handle.clone(), timeout) };
        trace!("[SKF_LockDev]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
        }
        Ok(())
    }

    #[instrument]
    fn unlock(&self) -> Result<()> {
        let func = self.symbols.dev_unlock.as_ref().expect("Symbol not load");
        let ret = unsafe { func(self.handle.clone()) };
        trace!("[SKF_UnlockDev]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
        }
        Ok(())
    }
    #[instrument]
    fn transmit(&self, command: &[u8], recv_capacity: u32) -> Result<Vec<u8>> {
        let func = self.symbols.dev_transmit.as_ref().expect("Symbol not load");
        let mut len: ULONG = recv_capacity as ULONG;
        let mut buffer = Vec::<u8>::with_capacity(recv_capacity as usize);
        let ret = unsafe {
            func(
                self.handle.clone(),
                command.as_ptr() as *const BYTE,
                command.len() as ULONG,
                buffer.as_mut_ptr() as *mut BYTE,
                &mut len,
            )
        };
        trace!("[SKF_Transmit]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
        }
        trace!("[SKF_Transmit]: output len = {}", len);
        unsafe { buffer.set_len(len as usize) };
        Ok(buffer)
    }
}

impl AppManager for SkfDeviceImpl {
    #[instrument]
    fn enumerate_app(&self) -> Result<Vec<String>> {
        let func = self.symbols.app_enum.as_ref().expect("Symbol not load");
        let mut len: ULONG = 0;
        let ret = unsafe { func(self.handle.clone(), std::ptr::null_mut(), &mut len) };
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
        }
        let mut buff = Vec::<CHAR>::with_capacity(len as usize);
        let ret = unsafe { func(self.handle.clone(), buff.as_mut_ptr(), &mut len) };
        trace!("[SKF_EnumApplication]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
        }
        unsafe { buff.set_len(len as usize) };
        trace!(
            "[SKF_EnumApplication]: app list = {}",
            String::from_utf8_lossy(&buff)
        );
        // The spec says string list end with two '\0',but vendor may not do it
        let list = unsafe { mem::parse_cstr_list_lossy(buff.as_ptr() as *const u8, buff.len()) };
        Ok(list)
    }

    #[instrument]
    fn create_app(&self, option: &CreateAppOption) -> Result<Box<dyn SkfApp>> {
        let func = self.symbols.app_create.as_ref().expect("Symbol not load");
        let name = param::as_cstring("option.name", &option.name)?;
        let admin_pin = param::as_cstring("option.admin_pin", &option.admin_pin)?;
        let user_pin = param::as_cstring("option.user_pin", &option.user_pin)?;
        let mut handle: HANDLE = std::ptr::null_mut();
        let ret = unsafe {
            func(
                self.handle.clone(),
                name.as_ptr() as *const CHAR,
                admin_pin.as_ptr() as *const CHAR,
                option.admin_pin_retry_count as DWORD,
                user_pin.as_ptr() as *const CHAR,
                option.user_pin_retry_count as DWORD,
                option.create_file_rights as DWORD,
                &mut handle,
            )
        };
        trace!("[SKF_CreateApplication]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
        }

        todo!()
    }

    #[instrument]
    fn open_app(&self, name: &str) -> Result<Box<dyn SkfApp>> {
        let func = self.symbols.app_open.as_ref().expect("Symbol not load");
        let name = param::as_cstring("name", name)?;
        let mut handle: HANDLE = std::ptr::null_mut();
        let ret = unsafe { func(self.handle.clone(), name.as_ptr() as LPSTR, &mut handle) };
        trace!("[SKF_OpenApplication]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
        }
        todo!()
    }

    #[instrument]
    fn delete_app(&self, name: &str) -> Result<()> {
        let func = self.symbols.app_delete.as_ref().expect("Symbol not load");
        let name = param::as_cstring("name", name)?;
        let mut handle: HANDLE = std::ptr::null_mut();
        let ret = unsafe { func(self.handle.clone(), name.as_ptr() as LPSTR) };
        trace!("[SKF_DeleteApplication]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
        }
        Ok(())
    }
}

impl SkfDevice for SkfDeviceImpl {}
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
            mem::parse_cstr_lossy(
                value.manufacturer.as_ptr() as *const u8,
                value.manufacturer.len(),
            )
            .unwrap_or("".to_string())
        };
        let issuer: String = unsafe {
            mem::parse_cstr_lossy(value.issuer.as_ptr() as *const u8, value.issuer.len())
                .unwrap_or("".to_string())
        };
        let label: String = unsafe {
            mem::parse_cstr_lossy(value.label.as_ptr() as *const u8, value.label.len())
                .unwrap_or("".to_string())
        };
        let serial_number = unsafe {
            mem::parse_cstr_lossy(
                value.serial_number.as_ptr() as *const u8,
                value.serial_number.len(),
            )
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
        let alg_sym_cap = value.alg_sym_cap as u32;
        let alg_asym_cap = value.alg_asym_cap as u32;
        let alg_hash_cap = value.alg_hash_cap as u32;
        let dev_auth_alg_id = value.dev_auth_alg_id as u32;
        let total_space = value.total_space as u32;
        let free_space = value.free_space as u32;
        let max_ecc_buffer_size = value.max_ecc_buffer_size as u32;
        let max_buffer_size = value.max_buffer_size as u32;
        let reserved = value.reserved.clone();
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
