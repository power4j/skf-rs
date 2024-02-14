mod engine;
mod error;
pub mod helper;
pub mod spec;

use skf_api::native::types::HANDLE;
use std::time::Duration;

pub type Error = error::Error;
pub type Result<T> = std::result::Result<T, Error>;

pub type Engine = engine::Engine;
pub type LibLoader = engine::LibLoader;

#[derive(Debug)]
pub struct PluginEvent {
    pub device_name: String,
    pub event: u8,
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
#[derive(Debug, Default)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

#[derive(Debug)]
pub struct DeviceInformation {
    pub version: Version,
    pub manufacturer: String,
    pub issuer: String,
    pub label: String,
    pub serial_number: String,
    pub hw_version: Version,
    pub firmware_version: Version,
    pub alg_sym_cap: u32,
    pub alg_asym_cap: u32,
    pub alg_hash_cap: u32,
    pub dev_auth_alg_id: u32,
    pub total_space: u32,
    pub free_space: u32,
    pub max_ecc_buffer_size: u32,
    pub max_buffer_size: u32,
    pub reserved: [u8; 64],
}

pub const DEV_STATE_ABSENT: u32 = 0;
pub const DEV_STATE_PRESENT: u32 = 1;
pub const DEV_STATE_UNKNOWN: u32 = 2;

pub trait DeviceManager {
    /// Enumerate all devices
    ///
    /// [presented_only] - Enumerate only presented devices,false means list all supported devices by underlying driver
    fn enumerate_device_name(&self, presented_only: bool) -> Result<Vec<String>>;

    /// Get device state
    ///
    /// [device_name] - The device name
    ///
    /// # state value
    /// - [DEV_STATE_ABSENT]
    /// - [DEV_STATE_PRESENT]
    /// - [DEV_STATE_UNKNOWN]
    fn device_state(&self, device_name: &str) -> Result<u32>;

    /// Wait for plug event,This function will block current thread
    ///
    /// If error happens, Error will be returned,otherwise `Some(PluginEvent)` will be returned
    ///
    /// `Ok(None)` means no event
    fn wait_plug_event(&self) -> Result<Option<PluginEvent>>;

    /// Cancel wait for plug event
    fn cancel_wait_plug_event(&self) -> Result<()>;

    /// Connect device with device name
    ///
    /// [device_name] - The device name
    fn connect(&self, device_name: &str) -> Result<Box<dyn SkfDevice>>;

    /// Connect to device by enumerate all devices and select one,if no device matches the selector, None will be returned
    ///
    /// [selector] - The device selector,if device list is not empty, the selector will be invoked to select one
    fn connect_selected(
        &self,
        selector: fn(Vec<&str>) -> Option<&str>,
    ) -> Result<Option<Box<dyn SkfDevice>>>;
}

pub trait DeviceCtl {
    /// Set label of device
    ///
    /// [label] - The label.
    ///
    /// # specification note
    /// - `label`: should less than 32 bytes
    fn set_label(&self, label: &str) -> Result<()>;

    /// Get device info,e.g. vendor id,product id
    fn info(&self) -> Result<DeviceInformation>;

    /// Lock device for exclusive access
    ///
    /// [timeout] - The lock timeout,`None` means wait forever
    fn lock(&self, timeout: Option<Duration>) -> Result<()>;

    /// Unlock device
    fn unlock(&self) -> Result<()>;

    /// Transmit data to execute,and get response
    ///
    /// [command] - The command to execute
    ///
    /// [recv_capacity] - The capacity of receive buffer
    /// # specification note
    ///
    /// This function is for testing purpose
    fn transmit(&self, command: &[u8], recv_capacity: usize) -> Result<Vec<u8>>;

    /// Generate random data
    ///
    /// [len] - The random data length to generate,in bytes
    fn gen_random(&self, len: usize) -> Result<Vec<u8>>;

    /// Import plain symmetric key(AKA session key)
    ///
    /// [alg_id] - The algorithm id,see [CryptoAlgorithm]
    ///
    /// [key] - The symmetric key
    /// ## Owner object lifetime requirement
    /// If owner object([SkfDevice]) is dropped, the key will be invalid
    fn set_symmetric_key(&self, alg_id: u32, key: &[u8]) -> Result<Box<dyn ManagedKey>>;
}

#[derive(Debug, Default)]
pub struct AppAttr {
    pub admin_pin: String,
    pub admin_pin_retry_count: u32,
    pub user_pin: String,
    pub user_pin_retry_count: u32,
    pub create_file_rights: u32,
}

pub trait AppManager {
    ///  Enumerate all apps in the device,return app names
    fn enumerate_app_name(&self) -> Result<Vec<String>>;

    /// Create app in the device
    ///
    /// [name] - The app name
    ///
    /// [attr] - The attribute of app
    /// ## Owner object lifetime requirement
    /// If owner object([SkfDevice]) is dropped, the `SkfApp` object will be invalid
    fn create_app(&self, name: &str, attr: &AppAttr) -> Result<Box<dyn SkfApp>>;

    /// Open app
    ///
    /// [name] - The app name to open
    /// ## Owner object lifetime requirement
    /// If owner object([SkfDevice]) is dropped, the `SkfApp` object will be invalid
    fn open_app(&self, name: &str) -> Result<Box<dyn SkfApp>>;
    /// Delete app
    ///
    /// [name] - The app name to delete
    fn delete_app(&self, name: &str) -> Result<()>;
}
pub trait DeviceSecurity {
    /// Device authentication
    ///
    /// [data] - The authentication data
    ///
    /// ## authentication process
    /// 1. Call the `SKF_GetRandom` function to get an 8-byte random number `RND` from the device,
    ///    and pads it to the block size of the cryptographic algorithm with `0x00` to form the data block `D0`
    /// 2. Encrypts `D0` to get the encrypted result `D1`, and calls `SKF_DevAuth`, sending `D1` to the device
    /// 3. Upon receiving `D1`, the device verifies whether `D1` is correct. If correct, the device authentication passes, otherwise the device authentication fails.
    fn device_auth(&self, data: &[u8]) -> Result<()>;

    /// Change device authentication key
    ///
    /// [key] - The new authentication key
    fn change_device_auth_key(&self, key: &[u8]) -> Result<()>;
}

/// Represents a device instance,call `DeviceManager::connect()` or `DeviceManager::connect_selected()` to get one
/// ## Disconnect
/// Device instance is disconnected when `Drop`
pub trait SkfDevice: DeviceCtl + DeviceSecurity + AppManager {
    /// get block cipher service
    fn block_cipher(&self) -> Result<Box<dyn SkfBlockCipher + Send + Sync>>;
}

/// PIN type: Admin
pub const PIN_TYPE_ADMIN: u8 = 0;

/// PIN type: User
pub const PIN_TYPE_USER: u8 = 1;

/// PIN information
#[derive(Debug, Default)]
pub struct PinInfo {
    pub max_retry_count: u32,
    pub remain_retry_count: u32,
    pub default_pin: bool,
}
pub trait AppSecurity {
    /// Lock device for exclusive access
    ///
    /// [pin_type] - The pin type, can be `PIN_TYPE_ADMIN` or `PIN_TYPE_USER`
    ///
    /// [old_pin] - The old pin
    ///
    /// [new_pin] - The new pin
    ///
    /// ## specification note
    /// - PIN verification failed: The value of remaining retry count will be returned, `0` means the PIN has been locked
    /// - PIN verification success: `None` will be returned
    ///
    /// ## Error
    /// - `Error::PinVerifyFailed` returned when PIN verification failed
    ///
    fn change_pin(&self, pin_type: u8, old_pin: &str, new_pin: &str) -> Result<()>;

    /// Verify PIN to get access rights
    ///
    /// [pin_type] - The pin type,can be `PIN_TYPE_ADMIN` or `PIN_TYPE_USER`
    ///
    /// [pin] - The pin value
    /// ## specification note
    /// - PIN verification failed: The value of remaining retry count will be returned, `0` means the PIN has been locked
    /// - PIN verification success: `None` will be returned
    ///
    /// ## Error
    /// - `Error::PinVerifyFailed` returned when PIN verification failed
    fn verify_pin(&self, pin_type: u8, pin: &str) -> Result<()>;

    /// Get PIN info
    ///
    /// [pin_type] - The pin type,can be `PIN_TYPE_ADMIN` or `PIN_TYPE_USER`
    fn pin_info(&self, pin_type: u8) -> Result<PinInfo>;

    /// Unlock user PIN
    ///
    /// [admin_pin] - The admin PIN
    ///
    /// [new_pin] - The new PIN
    ///
    /// [recv_capacity] - The capacity of receive buffer
    /// # specification note
    /// - PIN verification failed: The value of remaining retry count will be returned, `0` means the PIN has been locked
    /// - PIN verification success: `None` will be returned
    ///
    /// ## Error
    /// - `Error::PinVerifyFailed` returned when PIN verification failed
    fn unblock_pin(&self, admin_pin: &str, new_pin: &str) -> Result<()>;

    /// Clear secure state
    fn clear_secure_state(&self) -> Result<()>;
}

/// File permission: none
pub const FILE_PERM_NONE: u32 = 0x00000000;
/// File permission: permit to admin account
pub const FILE_PERM_ADMIN: u32 = 0x00000001;
/// File permission: permit to user account
pub const FILE_PERM_USER: u32 = 0x00000010;
/// File permission: permit to everyone
pub const FILE_PERM_EVERYONE: u32 = 0x000000FF;
#[derive(Debug, Default)]
pub struct FileAttr {
    pub file_name: String,
    pub file_size: usize,
    pub read_rights: u32,
    pub write_rights: u32,
}

#[derive(Debug)]
pub struct FileAttrBuilder {
    file_name: String,
    file_size: usize,
    read_rights: u32,
    write_rights: u32,
}
pub trait FileManager {
    ///  Enumerate all file in the app,return file names
    fn enumerate_file_name(&self) -> Result<Vec<String>>;

    /// Create file in the app
    ///
    ///[attr] - The file attribute
    ///
    /// ## file name
    ///
    /// The file name,should less than 32 bytes, It will be truncated if it is too long
    fn create_file(&self, attr: &FileAttr) -> Result<()>;

    /// Delete file from app
    ///
    /// [name] - The file name to delete
    fn delete_file(&self, name: &str) -> Result<()>;
    /// Read data from file
    ///
    /// [name] - The file name
    ///
    /// [offset] - File offset to read
    ///
    /// [size] - Read size,in bytes
    ///
    /// ## specification note
    /// actual read size may be less than [size]
    fn read_file(&self, name: &str, offset: u32, size: usize) -> Result<Vec<u8>>;
    /// Write date to file
    ///
    /// [name] - The file name
    ///
    /// [offset] - File offset to write
    ///
    /// [data] - The data to write
    fn write_file(&self, name: &str, offset: u32, data: &[u8]) -> Result<()>;
    /// Get file attribute info
    ///
    /// [name] - The file name
    fn get_file_info(&self, name: &str) -> Result<FileAttr>;
}

pub trait ContainerManager {
    ///  Enumerate all apps in the app,return container names
    fn enumerate_container_name(&self) -> Result<Vec<String>>;

    /// Create container in the app
    ///
    /// [name] - The container name
    fn create_container(&self, name: &str) -> Result<Box<dyn SkfContainer>>;

    /// Open container by  name
    ///
    /// [name] - The container name
    fn open_container(&self, name: &str) -> Result<Box<dyn SkfContainer>>;

    /// Delete container by name
    ///
    /// [name] - The container name
    fn delete_container(&self, name: &str) -> Result<()>;
}

/// Represents an Application instance
/// ## Close
/// Application instance is closed when `Drop`
pub trait SkfApp: AppSecurity + FileManager + ContainerManager {}

const CONTAINER_TYPE_UNKNOWN: u32 = 0;
const CONTAINER_TYPE_RSA: u32 = 0;
const CONTAINER_TYPE_ECC: u32 = 0;

/// Represents a Container instance
/// ## Close
/// Container instance is closed when `Drop`
/// ## Owner object lifetime requirement
/// If owner object([SkfApp]) is dropped, the `SkfContainer` object will be invalid
pub trait SkfContainer {
    /// Get container type,the value of type can be:
    /// - [CONTAINER_TYPE_UNKNOWN]
    /// - [CONTAINER_TYPE_RSA]
    /// - [CONTAINER_TYPE_ECC]
    fn get_type(&self) -> Result<u32>;

    /// Import certificate to container
    ///
    /// [signer] - True means The imported certificate is used for sign
    ///
    /// [data] - The certificate data
    fn import_certificate(&self, signer: bool, data: &[u8]) -> Result<()>;

    /// Export certificate from container
    ///
    /// [signer] - True means The exported certificate is used for sign
    fn export_certificate(&self, signer: bool) -> Result<Vec<u8>>;
}

#[derive(Debug, Default)]
pub struct BlockCipherParameter {
    /// IV data,max 32 bytes,Empty means no IV
    pub iv: Vec<u8>,
    /// padding type,
    /// - 0: None
    /// - 1: PKCS7
    pub padding_type: u8,
    pub feed_bit_len: u32,
}

/// Represents a key object
/// ## Close
/// key object is closed when `Drop`
pub trait ManagedKey: AsRef<HANDLE> {}

/// Block cipher service
pub trait SkfBlockCipher {
    /// Initialize encryption
    ///
    /// [key] - The key object
    ///
    /// [param] - The encryption parameter
    fn encrypt_init(&self, key: &dyn ManagedKey, param: &BlockCipherParameter) -> Result<()>;

    /// Encrypt data
    ///
    /// [data] - The data to encrypt
    ///
    /// [buffer_size] - The buffer size to receive encrypted data,it depends on the encryption parameter passed by `encrypt_init` and crypto algorithm
    ///
    /// see `SKF_Encrypt` for more details
    fn encrypt(&self, key: &dyn ManagedKey, data: &[u8], buffer_size: usize) -> Result<Vec<u8>>;

    /// Encrypting multiple groups of data.
    ///
    /// [data] - The data to encrypt
    ///
    /// [buffer_size] - The buffer size to receive encrypted data,it depends on the encryption parameter passed by `encrypt_init` and crypto algorithm
    ///
    /// see `SKF_EncryptUpdate` for more details
    fn encrypt_update(
        &self,
        key: &dyn ManagedKey,
        data: &[u8],
        buffer_size: usize,
    ) -> Result<Vec<u8>>;

    /// Finish encrypting multiple groups of data, return the remaining encrypted result
    ///
    /// [buffer_size] - The buffer size to receive encrypted data,it depends on the encryption parameter passed by `encrypt_init` and crypto algorithm
    ///
    /// see `SKF_EncryptFinal` for more details
    fn encrypt_final(&self, key: &dyn ManagedKey, buffer_size: usize) -> Result<Vec<u8>>;

    /// Initialize decryption
    ///
    /// [key] - The key object
    ///
    /// [param] - The decryption parameter
    ///
    /// see `SKF_DecryptInit` for more details
    fn decrypt_init(&self, key: &dyn ManagedKey, param: &BlockCipherParameter) -> Result<()>;

    /// Decrypt data
    ///
    /// [data] - The data to decrypt
    ///
    /// [buffer_size] - The buffer size to receive decrypted data,it depends on the decryption parameter passed by `decrypt_init` and crypto algorithm
    ///
    /// see `SKF_Decrypt` for more details
    fn decrypt(&self, key: &dyn ManagedKey, data: &[u8], buffer_size: usize) -> Result<Vec<u8>>;

    /// Decrypting multiple groups of data.
    ///
    /// [data] - The data to decrypt
    ///
    /// [buffer_size] - The buffer size to receive decrypted data,it depends on the encryption parameter passed by `decrypt_init` and crypto algorithm
    ///
    /// see `SKF_EncryptUpdate` for more details
    fn decrypt_update(
        &self,
        key: &dyn ManagedKey,
        data: &[u8],
        buffer_size: usize,
    ) -> Result<Vec<u8>>;

    /// Finish decrypting multiple groups of data, return the remaining decrypted result
    ///
    /// [buffer_size] - The buffer size to receive decrypted data,it depends on the decryption parameter passed by `decrypt_init` and crypto algorithm
    ///
    /// see `SKF_EncryptFinal` for more details
    fn decrypt_final(&self, key: &dyn ManagedKey, buffer_size: usize) -> Result<Vec<u8>>;
}
