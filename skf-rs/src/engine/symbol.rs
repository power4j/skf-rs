use libloading::{Library, Symbol};
use skf_api::native::types::{ECCPublicKeyBlob, BOOL, BYTE, HANDLE, ULONG};
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
#[allow(non_camel_case_types)]
pub(crate) mod app_fn {
    use crate::engine::symbol::SymbolBundle;
    use skf_api::native::types::{FileAttribute, BOOL, BYTE, CHAR, HANDLE, LPSTR, ULONG};

    pub(super) type SKF_CloseApplication = SymbolBundle<unsafe extern "C" fn(HANDLE) -> ULONG>;
    pub(super) type SKF_CreateFile =
        SymbolBundle<unsafe extern "C" fn(HANDLE, LPSTR, ULONG, ULONG, ULONG) -> ULONG>;
    pub(super) type SKF_DeleteFile = SymbolBundle<unsafe extern "C" fn(HANDLE, LPSTR) -> ULONG>;
    pub(super) type SKF_EnumFiles =
        SymbolBundle<unsafe extern "C" fn(HANDLE, *mut CHAR, *mut ULONG) -> ULONG>;
    pub(super) type SKF_GetFileInfo =
        SymbolBundle<unsafe extern "C" fn(HANDLE, LPSTR, *mut FileAttribute) -> ULONG>;
    pub(super) type SKF_ReadFile = SymbolBundle<
        unsafe extern "C" fn(HANDLE, LPSTR, ULONG, ULONG, *mut BYTE, *mut ULONG) -> ULONG,
    >;
    pub(super) type SKF_WriteFile =
        SymbolBundle<unsafe extern "C" fn(HANDLE, LPSTR, ULONG, *const BYTE, ULONG) -> ULONG>;

    pub(super) type SKF_ChangePIN =
        SymbolBundle<unsafe extern "C" fn(HANDLE, ULONG, LPSTR, LPSTR, *mut ULONG) -> ULONG>;

    pub(super) type SKF_GetPINInfo = SymbolBundle<
        unsafe extern "C" fn(HANDLE, ULONG, *mut ULONG, *mut ULONG, *mut BOOL) -> ULONG,
    >;

    pub(super) type SKF_VerifyPIN =
        SymbolBundle<unsafe extern "C" fn(HANDLE, ULONG, LPSTR, *mut ULONG) -> ULONG>;

    pub(super) type SKF_UnblockPIN =
        SymbolBundle<unsafe extern "C" fn(HANDLE, LPSTR, LPSTR, *mut ULONG) -> ULONG>;

    pub(super) type SKF_ClearSecureState = SymbolBundle<unsafe extern "C" fn(HANDLE) -> ULONG>;
}

#[allow(non_camel_case_types)]
pub(crate) mod container_fn {
    use crate::engine::symbol::SymbolBundle;
    use skf_api::native::types::{BOOL, BYTE, CHAR, HANDLE, LPSTR, ULONG};

    pub(super) type SKF_CreateContainer =
        SymbolBundle<unsafe extern "C" fn(HANDLE, LPSTR, *mut HANDLE) -> ULONG>;
    pub(super) type SKF_DeleteContainer =
        SymbolBundle<unsafe extern "C" fn(HANDLE, LPSTR) -> ULONG>;
    pub(super) type SKF_OpenContainer =
        SymbolBundle<unsafe extern "C" fn(HANDLE, LPSTR, *mut HANDLE) -> ULONG>;
    pub(super) type SKF_EnumContainer =
        SymbolBundle<unsafe extern "C" fn(HANDLE, *mut CHAR, *mut ULONG) -> ULONG>;
    pub(super) type SKF_CloseContainer = SymbolBundle<unsafe extern "C" fn(HANDLE) -> ULONG>;
    pub(super) type SKF_GetContainerType =
        SymbolBundle<unsafe extern "C" fn(HANDLE, *mut ULONG) -> ULONG>;
    pub(super) type SKF_ImportCertificate =
        SymbolBundle<unsafe extern "C" fn(HANDLE, BOOL, *const BYTE, ULONG) -> ULONG>;
    pub(super) type SKF_ExportCertificate =
        SymbolBundle<unsafe extern "C" fn(HANDLE, BOOL, *mut BYTE, *mut ULONG) -> ULONG>;
}

#[allow(non_camel_case_types)]
pub(crate) mod crypto_fn {
    use crate::engine::symbol::SymbolBundle;
    use skf_api::native::types::{
        BlockCipherParam, ECCCipherBlob, ECCPrivateKeyBlob, ECCPublicKeyBlob, ECCSignatureBlob,
        EnvelopedKeyBlob, BOOL, BYTE, HANDLE, ULONG,
    };
    pub(crate) type SKF_GenRandom =
        SymbolBundle<unsafe extern "C" fn(HANDLE, *mut BYTE, ULONG) -> ULONG>;
    pub(crate) type SKF_CloseHandle = SymbolBundle<unsafe extern "C" fn(HANDLE) -> ULONG>;
    pub(super) type SKF_SetSymmKey =
        SymbolBundle<unsafe extern "C" fn(HANDLE, *const BYTE, ULONG, *mut HANDLE) -> ULONG>;
    pub(super) type SKF_EncryptInit =
        SymbolBundle<unsafe extern "C" fn(HANDLE, BlockCipherParam) -> ULONG>;
    pub(super) type SKF_Encrypt = SymbolBundle<
        unsafe extern "C" fn(HANDLE, *const BYTE, ULONG, *mut BYTE, *mut ULONG) -> ULONG,
    >;
    pub(super) type SKF_EncryptUpdate = SymbolBundle<
        unsafe extern "C" fn(HANDLE, *const BYTE, ULONG, *mut BYTE, *mut ULONG) -> ULONG,
    >;
    pub(super) type SKF_EncryptFinal =
        SymbolBundle<unsafe extern "C" fn(HANDLE, *mut BYTE, *mut ULONG) -> ULONG>;
    pub(super) type SKF_DecryptInit =
        SymbolBundle<unsafe extern "C" fn(HANDLE, BlockCipherParam) -> ULONG>;
    pub(super) type SKF_Decrypt = SymbolBundle<
        unsafe extern "C" fn(HANDLE, *const BYTE, ULONG, *mut BYTE, *mut ULONG) -> ULONG,
    >;
    pub(super) type SKF_DecryptUpdate = SymbolBundle<
        unsafe extern "C" fn(HANDLE, *const BYTE, ULONG, *mut BYTE, *mut ULONG) -> ULONG,
    >;
    pub(super) type SKF_DecryptFinal =
        SymbolBundle<unsafe extern "C" fn(HANDLE, *mut BYTE, *mut ULONG) -> ULONG>;

    pub(super) type SKF_ExtECCEncrypt = SymbolBundle<
        unsafe extern "C" fn(
            HANDLE,
            *const ECCPublicKeyBlob,
            *const BYTE,
            ULONG,
            *mut ECCCipherBlob,
        ) -> ULONG,
    >;

    pub(super) type SKF_ExtECCDecrypt = SymbolBundle<
        unsafe extern "C" fn(
            HANDLE,
            *const ECCPrivateKeyBlob,
            *const ECCCipherBlob,
            *mut BYTE,
            *mut ULONG,
        ) -> ULONG,
    >;

    pub(super) type SKF_ExtECCSign = SymbolBundle<
        unsafe extern "C" fn(
            HANDLE,
            *const ECCPrivateKeyBlob,
            *const BYTE,
            ULONG,
            *mut ECCSignatureBlob,
        ) -> ULONG,
    >;

    pub(super) type SKF_ExtECCVerify = SymbolBundle<
        unsafe extern "C" fn(
            HANDLE,
            *const ECCPublicKeyBlob,
            *const BYTE,
            ULONG,
            *const ECCSignatureBlob,
        ) -> ULONG,
    >;
    pub(super) type SKF_GenECCKeyPair =
        SymbolBundle<unsafe extern "C" fn(HANDLE, ULONG, key_blob: *mut ECCPublicKeyBlob) -> ULONG>;

    pub(super) type SKF_ImportECCKeyPair =
        SymbolBundle<unsafe extern "C" fn(HANDLE, *const EnvelopedKeyBlob) -> ULONG>;

    pub(super) type SKF_ECCSignData = SymbolBundle<
        unsafe extern "C" fn(HANDLE, *const BYTE, ULONG, *mut ECCSignatureBlob) -> ULONG,
    >;

    pub(super) type SKF_ECCVerify = SymbolBundle<
        unsafe extern "C" fn(
            HANDLE,
            *const ECCPublicKeyBlob,
            *const BYTE,
            ULONG,
            *const ECCSignatureBlob,
        ) -> ULONG,
    >;

    pub(super) type SKF_ECCExportSessionKey = SymbolBundle<
        unsafe extern "C" fn(
            HANDLE,
            ULONG,
            *const ECCPublicKeyBlob,
            *mut ECCCipherBlob,
            *mut HANDLE,
        ) -> ULONG,
    >;

    pub(super) type SKF_GenerateAgreementDataWithECC = SymbolBundle<
        unsafe extern "C" fn(
            HANDLE,
            ULONG,
            *mut ECCPublicKeyBlob,
            *const BYTE,
            ULONG,
            *mut HANDLE,
        ) -> ULONG,
    >;

    pub(super) type SKF_GenerateAgreementDataAndKeyWithECC = SymbolBundle<
        unsafe extern "C" fn(
            HANDLE,
            ULONG,
            *const ECCPublicKeyBlob,
            *const ECCPublicKeyBlob,
            *mut ECCPublicKeyBlob,
            *const BYTE,
            ULONG,
            *const BYTE,
            ULONG,
            *mut HANDLE,
        ) -> ULONG,
    >;

    pub(super) type SKF_ExportPublicKey = SymbolBundle<
        unsafe extern "C" fn(
            HANDLE,
            sign_flag: BOOL,
            data: *mut BYTE,
            data_len: *mut ULONG,
        ) -> ULONG,
    >;

    pub(super) type SKF_ImportSessionKey = SymbolBundle<
        unsafe extern "C" fn(
            HANDLE,
            ULONG,
            data: *const BYTE,
            data_len: ULONG,
            key_handle: *mut HANDLE,
        ) -> ULONG,
    >;

    pub(super) type SKF_GenerateKeyWithECC = SymbolBundle<
        unsafe extern "C" fn(
            agreement_key: HANDLE,
            *const ECCPublicKeyBlob,
            *const ECCPublicKeyBlob,
            *const BYTE,
            ULONG,
            *mut HANDLE,
        ) -> ULONG,
    >;
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
    pub gen_random: Option<crypto_fn::SKF_GenRandom>,
    pub sym_key_import: Option<crypto_fn::SKF_SetSymmKey>,
    pub ecc_ext_encrypt: Option<crypto_fn::SKF_ExtECCEncrypt>,
    pub ecc_ext_decrypt: Option<crypto_fn::SKF_ExtECCDecrypt>,
    pub ecc_ext_sign: Option<crypto_fn::SKF_ExtECCSign>,
    pub ecc_ext_verify: Option<crypto_fn::SKF_ExtECCVerify>,
    pub ecc_verify: Option<crypto_fn::SKF_ECCVerify>,
    pub ecc_gen_sk: Option<crypto_fn::SKF_GenerateKeyWithECC>,
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
        let gen_random = Some(unsafe { SymbolBundle::new(lib, b"SKF_GenRandom\0")? });
        let sym_key_import = Some(unsafe { SymbolBundle::new(lib, b"SKF_SetSymmKey\0")? });
        let ecc_ext_encrypt = Some(unsafe { SymbolBundle::new(lib, b"SKF_ExtECCEncrypt\0")? });
        let ecc_ext_decrypt = Some(unsafe { SymbolBundle::new(lib, b"SKF_ExtECCDecrypt\0")? });
        let ecc_ext_sign = Some(unsafe { SymbolBundle::new(lib, b"SKF_ExtECCSign\0")? });
        let ecc_ext_verify = Some(unsafe { SymbolBundle::new(lib, b"SKF_ExtECCVerify\0")? });
        let ecc_verify = Some(unsafe { SymbolBundle::new(lib, b"SKF_ECCVerify\0")? });
        let ecc_gen_sk = Some(unsafe { SymbolBundle::new(lib, b"SKF_GenerateKeyWithECC\0")? });

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
            gen_random,
            sym_key_import,
            ecc_ext_encrypt,
            ecc_ext_decrypt,
            ecc_ext_sign,
            ecc_ext_verify,
            ecc_verify,
            ecc_gen_sk,
        };
        Ok(holder)
    }
}

#[derive(Default)]
pub(crate) struct ModApp {
    pub app_close: Option<app_fn::SKF_CloseApplication>,
    pub app_clear_secure_state: Option<app_fn::SKF_ClearSecureState>,
    pub file_get_list: Option<app_fn::SKF_EnumFiles>,
    pub file_create: Option<app_fn::SKF_CreateFile>,
    pub file_delete: Option<app_fn::SKF_DeleteFile>,
    pub file_get_info: Option<app_fn::SKF_GetFileInfo>,
    pub file_read: Option<app_fn::SKF_ReadFile>,
    pub file_write: Option<app_fn::SKF_WriteFile>,
    pub container_get_list: Option<container_fn::SKF_EnumContainer>,
    pub container_create: Option<container_fn::SKF_CreateContainer>,
    pub container_delete: Option<container_fn::SKF_DeleteContainer>,
    pub container_open: Option<container_fn::SKF_OpenContainer>,
    pub pin_change: Option<app_fn::SKF_ChangePIN>,
    pub pin_get_info: Option<app_fn::SKF_GetPINInfo>,
    pub pin_verify: Option<app_fn::SKF_VerifyPIN>,
    pub pin_unblock: Option<app_fn::SKF_UnblockPIN>,
}

impl ModApp {
    pub fn load_symbols(lib: &Arc<Library>) -> crate::Result<Self> {
        let app_close = Some(unsafe { SymbolBundle::new(lib, b"SKF_CloseApplication\0")? });
        let app_clear_secure_state =
            Some(unsafe { SymbolBundle::new(lib, b"SKF_ClearSecureState\0")? });
        let file_get_list = Some(unsafe { SymbolBundle::new(lib, b"SKF_EnumFiles\0")? });
        let file_create = Some(unsafe { SymbolBundle::new(lib, b"SKF_CreateFile\0")? });
        let file_delete = Some(unsafe { SymbolBundle::new(lib, b"SKF_DeleteFile\0")? });
        let file_get_info = Some(unsafe { SymbolBundle::new(lib, b"SKF_GetFileInfo\0")? });
        let file_read = Some(unsafe { SymbolBundle::new(lib, b"SKF_ReadFile\0")? });
        let file_write = Some(unsafe { SymbolBundle::new(lib, b"SKF_WriteFile\0")? });
        let container_get_list = Some(unsafe { SymbolBundle::new(lib, b"SKF_EnumContainer\0")? });
        let container_create = Some(unsafe { SymbolBundle::new(lib, b"SKF_CreateContainer\0")? });
        let container_delete = Some(unsafe { SymbolBundle::new(lib, b"SKF_DeleteContainer\0")? });
        let container_open = Some(unsafe { SymbolBundle::new(lib, b"SKF_OpenContainer\0")? });

        let pin_change = Some(unsafe { SymbolBundle::new(lib, b"SKF_ChangePIN\0")? });
        let pin_get_info = Some(unsafe { SymbolBundle::new(lib, b"SKF_GetPINInfo\0")? });
        let pin_verify = Some(unsafe { SymbolBundle::new(lib, b"SKF_VerifyPIN\0")? });
        let pin_unblock = Some(unsafe { SymbolBundle::new(lib, b"SKF_UnblockPIN\0")? });

        let holder = Self {
            app_close,
            file_get_list,
            file_create,
            file_delete,
            file_get_info,
            file_read,
            file_write,
            container_get_list,
            container_create,
            container_delete,
            container_open,
            app_clear_secure_state,
            pin_change,
            pin_get_info,
            pin_verify,
            pin_unblock,
        };
        Ok(holder)
    }
}

#[derive(Default)]
pub(crate) struct ModContainer {
    pub ct_close: Option<container_fn::SKF_CloseContainer>,
    pub ct_get_type: Option<container_fn::SKF_GetContainerType>,
    pub ct_imp_cert: Option<container_fn::SKF_ImportCertificate>,
    pub ct_exp_cert: Option<container_fn::SKF_ExportCertificate>,
    pub ct_ecc_gen_pair: Option<crypto_fn::SKF_GenECCKeyPair>,
    pub ct_ecc_imp_pair: Option<crypto_fn::SKF_ImportECCKeyPair>,
    pub ct_ecc_sign: Option<crypto_fn::SKF_ECCSignData>,
    pub ct_ecc_verify: Option<crypto_fn::SKF_ECCVerify>,
    pub ct_sk_gen_agreement: Option<crypto_fn::SKF_GenerateAgreementDataWithECC>,
    pub ct_sk_gen_agreement_and_key: Option<crypto_fn::SKF_GenerateAgreementDataAndKeyWithECC>,
    pub ct_ecc_exp_pub_key: Option<crypto_fn::SKF_ExportPublicKey>,
    pub ct_sk_imp: Option<crypto_fn::SKF_ImportSessionKey>,
    pub ct_sk_exp: Option<crypto_fn::SKF_ECCExportSessionKey>,
}

impl ModContainer {
    pub fn load_symbols(lib: &Arc<Library>) -> crate::Result<Self> {
        let ct_close = Some(unsafe { SymbolBundle::new(lib, b"SKF_CloseContainer\0")? });
        let ct_get_type = Some(unsafe { SymbolBundle::new(lib, b"SKF_GetContainerType\0")? });
        let ct_imp_cert = Some(unsafe { SymbolBundle::new(lib, b"SKF_ImportCertificate\0")? });
        let ct_exp_cert = Some(unsafe { SymbolBundle::new(lib, b"SKF_ExportCertificate\0")? });
        let ct_ecc_gen_pair = Some(unsafe { SymbolBundle::new(lib, b"SKF_GenECCKeyPair\0")? });
        let ct_ecc_imp_pair = Some(unsafe { SymbolBundle::new(lib, b"SKF_ImportECCKeyPair\0")? });
        let ct_ecc_sign = Some(unsafe { SymbolBundle::new(lib, b"SKF_ECCSignData\0")? });
        let ct_ecc_verify = Some(unsafe { SymbolBundle::new(lib, b"SKF_ECCVerify\0")? });
        let ct_sk_gen_agreement =
            Some(unsafe { SymbolBundle::new(lib, b"SKF_GenerateAgreementDataWithECC\0")? });
        let ct_sk_gen_agreement_and_key =
            Some(unsafe { SymbolBundle::new(lib, b"SKF_GenerateAgreementDataAndKeyWithECC\0")? });
        let ct_ecc_exp_pub_key = Some(unsafe { SymbolBundle::new(lib, b"SKF_ExportPublicKey\0")? });
        let ct_sk_imp = Some(unsafe { SymbolBundle::new(lib, b"SKF_ImportSessionKey\0")? });
        let ct_sk_exp = Some(unsafe { SymbolBundle::new(lib, b"SKF_ECCExportSessionKey\0")? });
        let holder = Self {
            ct_close,
            ct_get_type,
            ct_imp_cert,
            ct_exp_cert,
            ct_ecc_gen_pair,
            ct_ecc_imp_pair,
            ct_ecc_sign,
            ct_ecc_verify,
            ct_sk_gen_agreement,
            ct_sk_gen_agreement_and_key,
            ct_ecc_exp_pub_key,
            ct_sk_imp,
            ct_sk_exp,
        };
        Ok(holder)
    }
}

#[derive(Default)]
pub(crate) struct ModBlockCipher {
    pub encrypt_init: Option<crypto_fn::SKF_EncryptInit>,
    pub encrypt: Option<crypto_fn::SKF_Encrypt>,
    pub encrypt_update: Option<crypto_fn::SKF_EncryptUpdate>,
    pub encrypt_final: Option<crypto_fn::SKF_EncryptFinal>,
    pub decrypt_init: Option<crypto_fn::SKF_DecryptInit>,
    pub decrypt: Option<crypto_fn::SKF_Decrypt>,
    pub decrypt_update: Option<crypto_fn::SKF_DecryptUpdate>,
    pub decrypt_final: Option<crypto_fn::SKF_DecryptFinal>,
}

impl ModBlockCipher {
    pub fn load_symbols(lib: &Arc<Library>) -> crate::Result<Self> {
        let encrypt_init = Some(unsafe { SymbolBundle::new(lib, b"SKF_EncryptInit\0")? });
        let encrypt = Some(unsafe { SymbolBundle::new(lib, b"SKF_Encrypt\0")? });
        let encrypt_update = Some(unsafe { SymbolBundle::new(lib, b"SKF_EncryptUpdate\0")? });
        let encrypt_final = Some(unsafe { SymbolBundle::new(lib, b"SKF_EncryptFinal\0")? });

        let decrypt_init = Some(unsafe { SymbolBundle::new(lib, b"SKF_DecryptInit\0")? });
        let decrypt = Some(unsafe { SymbolBundle::new(lib, b"SKF_Decrypt\0")? });
        let decrypt_update = Some(unsafe { SymbolBundle::new(lib, b"SKF_DecryptUpdate\0")? });
        let decrypt_final = Some(unsafe { SymbolBundle::new(lib, b"SKF_DecryptFinal\0")? });
        let holder = Self {
            encrypt_init,
            encrypt,
            encrypt_update,
            encrypt_final,
            decrypt_init,
            decrypt,
            decrypt_update,
            decrypt_final,
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
        assert!(ModMag::load_symbols(&lib).is_ok());
    }

    #[test]
    #[ignore]
    fn sym_mod_dev_test() {
        let lib = Arc::new(LibLoader::env_lookup().unwrap());
        assert!(ModDev::load_symbols(&lib).is_ok());
    }
}
