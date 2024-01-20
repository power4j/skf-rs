use crate::engine::skf_dev::SkfDeviceImpl;
use crate::engine::symbol::ModCtl;
use crate::error::{InvalidArgumentError, SkfErr};
use crate::helper::mem;
use crate::{Error, Result};
use crate::{PluginEvent, SkfCtl, SkfDevice};
use skf_api::native::error::SAR_OK;
use skf_api::native::types::{BOOL, CHAR, DEV_HANDLE, ULONG};
use std::fmt::Debug;
use std::sync::Arc;
use tracing::{instrument, trace};

pub(crate) struct SkfCtlImpl {
    lib: Arc<libloading::Library>,
    symbols: ModCtl,
}

impl SkfCtlImpl {
    /// Initialize
    ///
    /// [lib] - The library handle
    pub fn new(lib: &Arc<libloading::Library>) -> Result<Self> {
        let lc = Arc::clone(lib);
        let symbols = ModCtl::load_symbols(lib)?;
        Ok(Self { lib: lc, symbols })
    }
}

impl Debug for SkfCtlImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SkfCtlImpl")
    }
}

impl SkfCtl for SkfCtlImpl {
    #[instrument]
    fn enum_device(&self, presented_only: bool) -> Result<Vec<String>> {
        let func = self.symbols.enum_dev.as_ref().expect("Symbol not load");
        let mut len: ULONG = 0;
        let ret = unsafe { func(presented_only as BOOL, std::ptr::null_mut(), &mut len) };
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
        }
        let mut buff = Vec::<CHAR>::with_capacity(len as usize);
        let ret = unsafe { func(presented_only as BOOL, buff.as_mut_ptr(), &mut len) };
        trace!("[SKF_EnumDev]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
        }
        unsafe { buff.set_len(len as usize) };
        trace!(
            "[SKF_EnumDev]: device list = {}",
            String::from_utf8_lossy(&buff)
        );
        // The spec says string list end with two '\0',but vendor may not do it
        let list = unsafe { mem::parse_cstr_list_lossy(buff.as_ptr() as *const u8, buff.len()) };
        Ok(list)
    }

    #[instrument]
    fn device_state(&self, device_name: &str) -> Result<u32> {
        let func = self
            .symbols
            .get_dev_state
            .as_ref()
            .expect("Symbol not load");
        let device_name = std::ffi::CString::new(device_name).map_err(|e| {
            InvalidArgumentError::new(
                "parameter 'device_name' is invalid".to_string(),
                anyhow::Error::new(e),
            )
        })?;
        let mut satate: ULONG = 0;
        let ret = unsafe { func(device_name.as_ptr() as *const CHAR, &mut satate) };
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
        }
        Ok(satate as u32)
    }

    #[instrument]
    fn wait_plug_event(&self) -> Result<Option<PluginEvent>> {
        let func = self
            .symbols
            .wait_plug_event
            .as_ref()
            .expect("Symbol not load");
        let mut buff = Vec::<CHAR>::with_capacity(1024);
        let mut len: ULONG = buff.capacity() as ULONG;
        let mut event: ULONG = 0;
        let ret = unsafe { func(buff.as_mut_ptr(), &mut len, &mut event) };
        trace!("[SKF_WaitForDevEvent]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
        }
        trace!(
            "[SKF_WaitForDevEvent]: event = {},data len = {}",
            event,
            len
        );
        let name = unsafe { mem::parse_cstr_lossy(buff.as_ptr() as *const u8, len as usize) };
        let name = name.unwrap_or("".to_string());
        let event = event as u8;
        match event {
            PluginEvent::EVENT_PLUGGED_IN | PluginEvent::EVENT_UNPLUGGED => {
                Ok(Some(PluginEvent::new(name, event)))
            }
            _ => Ok(None),
        }
    }

    #[instrument]
    fn cancel_wait_plug_event(&self) -> Result<()> {
        let func = self
            .symbols
            .cancel_wait_plug_event
            .as_ref()
            .expect("Symbol not load");
        let ret = unsafe { func() };
        trace!("[SKF_CancelWaitForDevEvent]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
        }
        Ok(())
    }

    #[instrument]
    fn connect(&self, device_name: &str) -> Result<Box<dyn SkfDevice>> {
        let func = self.symbols.connect_dev.as_ref().expect("Symbol not load");
        let device_name = std::ffi::CString::new(device_name).map_err(|e| {
            InvalidArgumentError::new(
                "parameter 'device_name' is invalid".to_string(),
                anyhow::Error::new(e),
            )
        })?;
        let mut handle: DEV_HANDLE = std::ptr::null_mut();
        let ret = unsafe { func(device_name.as_ptr() as *const CHAR, &mut handle) };
        trace!("[SKF_ConnectDev]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::with_default_msg(ret)));
        }
        let dev = SkfDeviceImpl::new(handle, &self.lib)?;
        Ok(Box::new(dev))
    }

    fn connect_selected(
        &self,
        selector: fn(Vec<&str>) -> Option<&str>,
    ) -> Result<Option<Box<dyn SkfDevice>>> {
        let list = self.enum_device(true)?;
        if list.is_empty() {
            Ok(None)
        } else {
            let names: Vec<&str> = list.iter().map(|x| &**x).collect();
            if let Some(name) = selector(names) {
                let dev = self.connect(name)?;
                return Ok(Some(dev));
            }
            Ok(None)
        }
    }
}
