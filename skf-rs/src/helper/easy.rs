///!
/// Helper functions for use this library easily
///
use crate::{AppAttr, Result, SkfApp, SkfContainer, SkfDevice};

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
