use crate::engine::skf_dev::SkfDeviceImpl;
use crate::engine::symbol::ModApp;
use crate::error::{SkfErr, SkfPinVerifyError};
use crate::helper::param;
use crate::{AppSecurity, Error, PinInfo};
use skf_api::native::error::{SAR_OK, SAR_PIN_INCORRECT};
use skf_api::native::types::{BOOL, CHAR, FALSE, HANDLE, LPSTR, ULONG};
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
