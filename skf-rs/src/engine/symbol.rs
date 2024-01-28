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
pub(crate) mod device_fn {
    use super::SymbolBundle;
    use skf_api::native::types::{DeviceInfo, BOOL, BYTE, CHAR, DWORD, HANDLE, LPSTR, ULONG};

    pub(super) type SKF_WaitForDevEvent =
        SymbolBundle<unsafe extern "C" fn(*mut CHAR, *mut ULONG, *mut ULONG) -> ULONG>;

    pub(super) type SKF_CancelWaitForDevEvent = SymbolBundle<unsafe extern "C" fn() -> ULONG>;

    pub(super) type SKF_EnumDev =
        SymbolBundle<unsafe extern "C" fn(BOOL, *mut CHAR, *mut ULONG) -> ULONG>;

    pub(super) type SKF_GetDevState =
        SymbolBundle<unsafe extern "C" fn(*const CHAR, *mut ULONG) -> ULONG>;

    pub(super) type SKF_ConnectDev =
        SymbolBundle<unsafe extern "C" fn(*const CHAR, *mut HANDLE) -> ULONG>;

    pub(super) type SKF_DisConnectDev = SymbolBundle<unsafe extern "C" fn(HANDLE) -> ULONG>;

    pub(super) type SKF_SetLabel = SymbolBundle<unsafe extern "C" fn(HANDLE, *const CHAR) -> ULONG>;

    pub(super) type SKF_GetDevInfo =
        SymbolBundle<unsafe extern "C" fn(HANDLE, *mut DeviceInfo) -> ULONG>;

    pub(super) type SKF_LockDev = SymbolBundle<unsafe extern "C" fn(HANDLE, ULONG) -> ULONG>;

    pub(super) type SKF_UnlockDev = SymbolBundle<unsafe extern "C" fn(HANDLE) -> ULONG>;

    pub(super) type SKF_Transmit = SymbolBundle<
        unsafe extern "C" fn(HANDLE, *const BYTE, ULONG, *mut BYTE, *mut ULONG) -> ULONG,
    >;

    pub(super) type SKF_ChangeDevAuthKey =
        SymbolBundle<unsafe extern "C" fn(HANDLE, *const BYTE, ULONG) -> ULONG>;

    pub(super) type SKF_DevAuth =
        SymbolBundle<unsafe extern "C" fn(HANDLE, *const BYTE, ULONG) -> ULONG>;

    pub(super) type SKF_CreateApplication = SymbolBundle<
        unsafe extern "C" fn(
            HANDLE,
            LPSTR,
            LPSTR,
            DWORD,
            LPSTR,
            DWORD,
            DWORD,
            *mut HANDLE,
        ) -> ULONG,
    >;

    pub(super) type SKF_OpenApplication =
        SymbolBundle<unsafe extern "C" fn(HANDLE, LPSTR, *mut HANDLE) -> ULONG>;

    pub(super) type SKF_EnumApplication =
        SymbolBundle<unsafe extern "C" fn(HANDLE, *mut CHAR, *mut ULONG) -> ULONG>;
    pub(super) type SKF_DeleteApplication =
        SymbolBundle<unsafe extern "C" fn(HANDLE, LPSTR) -> ULONG>;
}

#[derive(Default)]
pub(crate) struct ModMag {
    pub enum_dev: Option<device_fn::SKF_EnumDev>,
    pub wait_plug_event: Option<device_fn::SKF_WaitForDevEvent>,
    pub cancel_wait_plug_event: Option<device_fn::SKF_CancelWaitForDevEvent>,
    pub get_dev_state: Option<device_fn::SKF_GetDevState>,
    pub connect_dev: Option<device_fn::SKF_ConnectDev>,
}

impl ModMag {
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
    pub dev_set_label: Option<device_fn::SKF_SetLabel>,
    pub dev_dis_connect: Option<device_fn::SKF_DisConnectDev>,
    pub dev_get_info: Option<device_fn::SKF_GetDevInfo>,
    pub dev_lock: Option<device_fn::SKF_LockDev>,
    pub dev_unlock: Option<device_fn::SKF_UnlockDev>,
    pub dev_transmit: Option<device_fn::SKF_Transmit>,
    pub dev_auth: Option<device_fn::SKF_DevAuth>,
    pub dev_change_auth_key: Option<device_fn::SKF_ChangeDevAuthKey>,
    pub app_create: Option<device_fn::SKF_CreateApplication>,
    pub app_open: Option<device_fn::SKF_OpenApplication>,
    pub app_delete: Option<device_fn::SKF_DeleteApplication>,
    pub app_enum: Option<device_fn::SKF_EnumApplication>,
}

impl ModDev {
    pub fn load_symbols(lib: &Arc<Library>) -> crate::Result<Self> {
        let dev_set_label = Some(unsafe { SymbolBundle::new(lib, b"SKF_SetLabel\0")? });
        let dev_dis_connect = Some(unsafe { SymbolBundle::new(lib, b"SKF_DisConnectDev\0")? });
        let dev_get_info = Some(unsafe { SymbolBundle::new(lib, b"SKF_GetDevInfo\0")? });
        let dev_lock = Some(unsafe { SymbolBundle::new(lib, b"SKF_LockDev\0")? });
        let dev_unlock = Some(unsafe { SymbolBundle::new(lib, b"SKF_UnlockDev\0")? });
        let dev_transmit = Some(unsafe { SymbolBundle::new(lib, b"SKF_Transmit\0")? });
        let dev_auth = Some(unsafe { SymbolBundle::new(lib, b"SKF_DevAuth\0")? });
        let dev_change_auth_key =
            Some(unsafe { SymbolBundle::new(lib, b"SKF_ChangeDevAuthKey\0")? });
        let app_create = Some(unsafe { SymbolBundle::new(lib, b"SKF_CreateApplication\0")? });
        let app_open = Some(unsafe { SymbolBundle::new(lib, b"SKF_OpenApplication\0")? });
        let app_delete = Some(unsafe { SymbolBundle::new(lib, b"SKF_DeleteApplication\0")? });
        let app_enum = Some(unsafe { SymbolBundle::new(lib, b"SKF_EnumApplication\0")? });
        let holder = Self {
            dev_set_label,
            dev_dis_connect,
            dev_get_info,
            dev_lock,
            dev_unlock,
            dev_transmit,
            dev_auth,
            dev_change_auth_key,
            app_create,
            app_open,
            app_delete,
            app_enum,
        };
        Ok(holder)
    }
}

#[derive(Default)]
pub(crate) struct ModApp {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::LibLoader;

    #[test]
    #[ignore]
    fn sym_mod_ctl_test() {
        let lib = Arc::new(LibLoader::env_lookup().unwrap());
        assert!(ModMag::load_symbols(&lib).is_ok());
    }

    #[test]
    #[ignore]
    fn sym_mod_dev_test() {
        let lib = Arc::new(LibLoader::env_lookup().unwrap());
        assert!(ModDev::load_symbols(&lib).is_ok());
    }
}
