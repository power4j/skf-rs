use crate::engine::device::SkfDeviceImpl;
use crate::engine::symbol::ModMag;
use crate::error::SkfErr;
use crate::helper::{mem, param};
use crate::{DeviceManager, PluginEvent, SkfDevice};
use crate::{Error, Result};
use skf_api::native::error::SAR_OK;
use skf_api::native::types::{BOOL, CHAR, HANDLE, ULONG};
use std::fmt::Debug;
use std::sync::Arc;
use tracing::{instrument, trace};

pub(crate) struct ManagerImpl {
    lib: Arc<libloading::Library>,
    symbols: ModMag,
}

impl ManagerImpl {
    /// Initialize
    ///
    /// [lib] - The library handle
    pub fn new(lib: &Arc<libloading::Library>) -> Result<Self> {
        let lc = Arc::clone(lib);
        let symbols = ModMag::load_symbols(lib)?;
        Ok(Self { lib: lc, symbols })
    }
}

impl Debug for ManagerImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ManagerImpl")
    }
}

impl DeviceManager for ManagerImpl {
    #[instrument]
    fn enumerate_device_name(&self, presented_only: bool) -> Result<Vec<String>> {
        let func = self.symbols.enum_dev.as_ref().expect("Symbol not load");
        let mut len: ULONG = 0;
        let ret = unsafe { func(presented_only as BOOL, std::ptr::null_mut(), &mut len) };
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        trace!("[SKF_EnumDev]: desired len = {}", len);
        if len == 0 {
            return Ok(vec![]);
        }
        let mut buff = Vec::<CHAR>::with_capacity(len as usize);
        let ret = unsafe { func(presented_only as BOOL, buff.as_mut_ptr(), &mut len) };
        trace!("[SKF_EnumDev]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        unsafe { buff.set_len(len as usize) };
        trace!(
            "[SKF_EnumDev]: device list = {}",
            String::from_utf8_lossy(&buff)
        );
        // The spec says string list end with two '\0',but vendor may not do it
        let list = unsafe { mem::parse_cstr_list_lossy(buff.as_ptr(), buff.len()) };
        Ok(list)
    }

    #[instrument]
    fn device_state(&self, device_name: &str) -> Result<u32> {
        let func = self
            .symbols
            .get_dev_state
            .as_ref()
            .expect("Symbol not load");
        let device_name = param::as_cstring("device_name", device_name)?;
        let mut satate: ULONG = 0;
        let ret = unsafe { func(device_name.as_ptr() as *const CHAR, &mut satate) };
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
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
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        trace!(
            "[SKF_WaitForDevEvent]: event = {},data len = {}",
            event,
            len
        );
        let name = unsafe { mem::parse_cstr_lossy(buff.as_ptr(), len as usize) };
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
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        Ok(())
    }

    #[instrument]
    fn connect(&self, device_name: &str) -> Result<Box<dyn SkfDevice>> {
        let func = self.symbols.connect_dev.as_ref().expect("Symbol not load");
        let device_name = param::as_cstring("device_name", device_name)?;
        let mut handle: HANDLE = std::ptr::null_mut();
        let ret = unsafe { func(device_name.as_ptr() as *const CHAR, &mut handle) };
        trace!("[SKF_ConnectDev]: ret = {}", ret);
        if ret != SAR_OK {
            return Err(Error::Skf(SkfErr::of_code(ret)));
        }
        let dev = SkfDeviceImpl::new(handle, &self.lib)?;
        Ok(Box::new(dev))
    }

    fn connect_selected(
        &self,
        selector: fn(Vec<&str>) -> Option<&str>,
    ) -> Result<Box<dyn SkfDevice>> {
        let list = self.enumerate_device_name(true)?;
        if list.is_empty() {
            Err(Error::NotFound("No device found".to_string()))
        } else {
            let names: Vec<&str> = list.iter().map(|x| &**x).collect();
            if let Some(name) = selector(names) {
                let dev = self.connect(name)?;
                return Ok(dev);
            }
            Err(Error::NotFound("No matched device".to_string()))
        }
    }
}

impl PluginEvent {
    /// The device is plugged in
    pub const EVENT_PLUGGED_IN: u8 = 1;

    /// The device is unplugged
    pub const EVENT_UNPLUGGED: u8 = 2;

    pub fn new(device_name: impl Into<String>, event: u8) -> Self {
        Self {
            device_name: device_name.into(),
            event,
        }
    }

    pub fn plugged_in(device_name: impl AsRef<str>) -> Self {
        Self {
            device_name: device_name.as_ref().to_string(),
            event: Self::EVENT_PLUGGED_IN,
        }
    }

    pub fn unplugged(device_name: impl AsRef<str>) -> Self {
        Self {
            device_name: device_name.as_ref().to_string(),
            event: Self::EVENT_UNPLUGGED,
        }
    }

    pub fn is_plugged_in(&self) -> bool {
        self.event == Self::EVENT_PLUGGED_IN
    }

    pub fn is_unplugged(&self) -> bool {
        self.event == Self::EVENT_UNPLUGGED
    }

    pub fn event_description(&self) -> &'static str {
        match self.event {
            Self::EVENT_PLUGGED_IN => "plugged in",
            Self::EVENT_UNPLUGGED => "unplugged",
            _ => "unknown",
        }
    }
}
