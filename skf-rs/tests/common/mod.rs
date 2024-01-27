use skf_rs::{DeviceManager, Engine, LibLoader, Result, SkfDevice};

pub fn chose_first(list: Vec<&str>) -> Option<&str> {
    Some(list[0])
}

pub fn device_manager() -> Result<Box<dyn DeviceManager + Send + Sync>> {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    engine.device_manager()
}

pub fn use_first_device() -> Result<Box<dyn SkfDevice>> {
    let manager = device_manager()?;
    let dev: Box<dyn SkfDevice> = manager.connect_selected(chose_first)?.unwrap();
    Ok(dev)
}
