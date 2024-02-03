use skf_rs::{
    CreateAppOption, DeviceManager, Engine, LibLoader, Result, SkfApp, SkfCrypto, SkfDevice,
    FILE_PERM_EVERYONE,
};

pub const TEST_APP_NAME_1: &str = "skf-rs-test-app-1";
pub const TEST_ADMIN_PIN: &str = "123456";
pub const TEST_USER_PIN: &str = "654321";

pub fn chose_first(list: Vec<&str>) -> Option<&str> {
    Some(list[0])
}

pub fn get_engine() -> Result<Engine> {
    let lib = LibLoader::env_lookup().expect("SKF Lib not load");
    let engine = Engine::new(lib);
    Ok(engine)
}
pub fn device_manager() -> Result<Box<dyn DeviceManager + Send + Sync>> {
    get_engine()?.device_manager()
}
pub fn use_crypto() -> Result<Box<dyn SkfCrypto + Send + Sync>> {
    get_engine()?.crypto()
}
pub fn use_first_device() -> Result<Box<dyn SkfDevice>> {
    let manager = device_manager()?;
    let dev: Box<dyn SkfDevice> = manager
        .connect_selected(chose_first)?
        .expect("SKF Device not found");
    Ok(dev)
}

pub fn get_or_create_test_app_1() -> Result<Box<dyn SkfApp>> {
    let opt = CreateAppOption {
        name: TEST_APP_NAME_1.to_string(),
        admin_pin: TEST_ADMIN_PIN.to_string(),
        admin_pin_retry_count: 8,
        user_pin: TEST_USER_PIN.to_string(),
        user_pin_retry_count: 8,
        create_file_rights: FILE_PERM_EVERYONE,
    };
    let dev = use_first_device()?;
    dev.create_app(&opt)
}
