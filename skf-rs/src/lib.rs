mod engine;
mod error;
pub mod helper;

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

pub trait SkfCtl {
    /// Enumerate all devices
    ///
    /// [presented_only] - Enumerate only presented devices,false means list all supported devices by underlying driver
    fn enum_device(&self, presented_only: bool) -> Result<Vec<String>>;

    /// Get device state
    ///
    /// [device_name] - The device name
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

pub trait SkfDevice {
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
    fn transmit(&self, command: &[u8], recv_capacity: u32) -> Result<Vec<u8>>;
}
