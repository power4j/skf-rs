use libloading::{Library, Symbol};
use std::sync::Arc;

/// Symbol bundle with library pointer
pub struct SymbolBundle<T: 'static> {
    _lib: Arc<Library>,
    symbol: Symbol<'static, T>,
}
impl<T> SymbolBundle<T> {
    /// Get a pointer to a function or static variable by symbol name.
    pub unsafe fn new(
        lib: &Arc<Library>,
        sym: &[u8],
    ) -> Result<SymbolBundle<T>, libloading::Error> {
        let lc = lib.clone();
        unsafe {
            let symbol: Symbol<T> = lib.get(sym)?;
            let bundle = SymbolBundle {
                _lib: lc,
                symbol: std::mem::transmute(symbol),
            };
            Ok(bundle)
        }
    }
}
impl<T> std::ops::Deref for SymbolBundle<T> {
    type Target = Symbol<'static, T>;
    fn deref(&self) -> &Self::Target {
        &self.symbol
    }
}

#[allow(non_camel_case_types)]
pub(crate) mod signature {
    use super::SymbolBundle;
    use skf_api::native::types::{DeviceInfo, BOOL, BYTE, CHAR, DEV_HANDLE, ULONG};

    pub(super) type SKF_WaitForDevEvent =
        SymbolBundle<unsafe extern "C" fn(*mut CHAR, *mut ULONG, *mut ULONG) -> ULONG>;

    pub(super) type SKF_CancelWaitForDevEvent = SymbolBundle<unsafe extern "C" fn() -> ULONG>;

    pub(super) type SKF_EnumDev =
        SymbolBundle<unsafe extern "C" fn(BOOL, *mut CHAR, *mut ULONG) -> ULONG>;

    pub(super) type SKF_GetDevState =
        SymbolBundle<unsafe extern "C" fn(*const CHAR, *mut ULONG) -> ULONG>;

    pub(super) type SKF_ConnectDev =
        SymbolBundle<unsafe extern "C" fn(*const CHAR, *mut DEV_HANDLE) -> ULONG>;

    pub(super) type SKF_DisConnectDev = SymbolBundle<unsafe extern "C" fn(DEV_HANDLE) -> ULONG>;

    pub(super) type SKF_SetLabel =
        SymbolBundle<unsafe extern "C" fn(DEV_HANDLE, *const CHAR) -> ULONG>;

    pub(super) type SKF_GetDevInfo =
        SymbolBundle<unsafe extern "C" fn(DEV_HANDLE, *mut DeviceInfo) -> ULONG>;

    pub(super) type SKF_LockDev = SymbolBundle<unsafe extern "C" fn(DEV_HANDLE, ULONG) -> ULONG>;

    pub(super) type SKF_UnlockDev = SymbolBundle<unsafe extern "C" fn(DEV_HANDLE) -> ULONG>;

    pub(super) type SKF_Transmit = SymbolBundle<
        unsafe extern "C" fn(DEV_HANDLE, *const BYTE, ULONG, *mut BYTE, *mut ULONG) -> ULONG,
    >;
}

#[derive(Default)]
pub(crate) struct ModCtl {
    pub enum_dev: Option<signature::SKF_EnumDev>,
    pub wait_plug_event: Option<signature::SKF_WaitForDevEvent>,
    pub cancel_wait_plug_event: Option<signature::SKF_CancelWaitForDevEvent>,
    pub get_dev_state: Option<signature::SKF_GetDevState>,
    pub connect_dev: Option<signature::SKF_ConnectDev>,
}

impl ModCtl {
    pub fn load_symbols(lib: &Arc<Library>) -> crate::Result<Self> {
        let enum_dev = Some(unsafe { SymbolBundle::new(lib, b"SKF_EnumDev\0")? });
        let wait_plug_event = Some(unsafe { SymbolBundle::new(lib, b"SKF_WaitForDevEvent\0")? });
        let cancel_wait_plug_event =
            Some(unsafe { SymbolBundle::new(lib, b"SKF_CancelWaitForDevEvent\0")? });
        let get_dev_state = Some(unsafe { SymbolBundle::new(lib, b"SKF_GetDevState\0")? });
        let connect_dev = Some(unsafe { SymbolBundle::new(lib, b"SKF_ConnectDev\0")? });
        let holder = Self {
            enum_dev,
            wait_plug_event,
            cancel_wait_plug_event,
            get_dev_state,
            connect_dev,
        };
        Ok(holder)
    }
}

#[derive(Default)]
pub(crate) struct ModDev {
    pub set_label: Option<signature::SKF_SetLabel>,
    pub dis_connect_dev: Option<signature::SKF_DisConnectDev>,
    pub get_info: Option<signature::SKF_GetDevInfo>,
    pub lock_dev: Option<signature::SKF_LockDev>,
    pub unlock_dev: Option<signature::SKF_UnlockDev>,
    pub transmit: Option<signature::SKF_Transmit>,
}

impl ModDev {
    pub fn load_symbols(lib: &Arc<Library>) -> crate::Result<Self> {
        let set_label = Some(unsafe { SymbolBundle::new(lib, b"SKF_SetLabel\0")? });
        let dis_connect_dev = Some(unsafe { SymbolBundle::new(lib, b"SKF_DisConnectDev\0")? });
        let get_info = Some(unsafe { SymbolBundle::new(lib, b"SKF_GetDevInfo\0")? });
        let lock_dev = Some(unsafe { SymbolBundle::new(lib, b"SKF_LockDev\0")? });
        let unlock_dev = Some(unsafe { SymbolBundle::new(lib, b"SKF_UnlockDev\0")? });
        let transmit = Some(unsafe { SymbolBundle::new(lib, b"SKF_Transmit\0")? });
        let holder = Self {
            set_label,
            dis_connect_dev,
            get_info,
            lock_dev,
            unlock_dev,
            transmit,
        };
        Ok(holder)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::LibLoader;

    #[test]
    #[ignore]
    fn sym_mod_ctl_test() {
        let lib = Arc::new(LibLoader::env_lookup().unwrap());
        assert!(ModCtl::load_symbols(&lib).is_ok());
    }

    #[test]
    #[ignore]
    fn sym_mod_dev_test() {
        let lib = Arc::new(LibLoader::env_lookup().unwrap());
        assert!(ModDev::load_symbols(&lib).is_ok());
    }
}
