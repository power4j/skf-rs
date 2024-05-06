//!
//! Helper functions for use this library easily
//!
use crate::{AppAttr, Result, SkfApp, SkfContainer, SkfDevice};
use tracing::{trace, warn};

/// Open or create application by it name
///
/// [device] - The device instance
///
/// [name] - The application name
///
/// [attr_fn] - A function to provide application attribute ,used when application is not exist
pub fn open_or_create_app(
    device: &dyn SkfDevice,
    name: &str,
    attr_fn: fn() -> AppAttr,
) -> Result<Box<dyn SkfApp>> {
    let list = device.enumerate_app_name()?;
    if list.contains(&name.to_string()) {
        return device.open_app(name);
    }
    device.create_app(name, &attr_fn())
}

/// Create application, If application exist, delete it first
///
/// [device] - The device instance
///
/// [name] - The application name
///
/// [attr_fn] - A function to provide application attribute
pub fn recreate_app(
    device: &dyn SkfDevice,
    name: &str,
    attr_fn: fn() -> AppAttr,
) -> Result<Box<dyn SkfApp>> {
    let list = device.enumerate_app_name()?;
    if list.contains(&name.to_string()) {
        device.delete_app(name)?;
    }
    device.create_app(name, &attr_fn())
}

/// Open or create container by container name
///
/// [app] - The application instance
///
/// [name] - The container name
pub fn open_or_create_container(app: &dyn SkfApp, name: &str) -> Result<Box<dyn SkfContainer>> {
    let list = app.enumerate_container_name()?;
    if list.contains(&name.to_string()) {
        return app.open_container(name);
    }
    app.create_container(name)
}

/// Create container, If container exist, delete it first
///
/// [app] - The application instance
///
/// [name] - The container name
pub fn recreate_container(app: &dyn SkfApp, name: &str) -> Result<Box<dyn SkfContainer>> {
    let list = app.enumerate_container_name()?;
    if list.contains(&name.to_string()) {
        app.delete_container(name)?;
    }
    app.create_container(name)
}

/// A wrapper for SkfApp, clean security state on drop
pub struct SecureApp {
    app: Box<dyn SkfApp>,
}

impl SecureApp {
    pub fn new(app: Box<dyn SkfApp>) -> Self {
        Self { app }
    }
}

impl Drop for SecureApp {
    fn drop(&mut self) {
        if let Some(err) = self.app.clear_secure_state() {
            warn!("Clear secure state failed: err = {}", err);
        }
    }
}

impl AsRef<dyn SkfApp> for SecureApp {
    fn as_ref(&self) -> &dyn SkfApp {
        self.app.as_ref()
    }
}
