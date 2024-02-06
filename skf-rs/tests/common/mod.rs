use skf_rs::helper::auth::encrypt_auth_key_sm1_ecb;
use skf_rs::{
    AppAttr, DeviceManager, Engine, LibLoader, Result, SkfApp, SkfContainer, SkfCrypto, SkfDevice,
    FILE_PERM_EVERYONE,
};

pub const TEST_APP_NAME_1: &str = "skf-rs-test-app-1";
pub const TEST_ADMIN_PIN: &str = "123456";
pub const TEST_USER_PIN: &str = "654321";
pub const TEST_FILE_NAME_1: &str = "skf-rs-test-file-1";
pub const TEST_CONTAINER_NAME_1: &str = "skf-rs-test-file-1";
pub const TEST_AUTH_KEY: [u8; 16] = [
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
];

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

pub fn use_first_device_with_auth() -> Result<Box<dyn SkfDevice>> {
    let manager = device_manager()?;
    let device: Box<dyn SkfDevice> = manager
        .connect_selected(chose_first)?
        .expect("SKF Device not found");
    let auth_key =
        encrypt_auth_key_sm1_ecb(device.as_ref(), &TEST_AUTH_KEY).expect("auth key encrypt failed");
    let _ = device
        .device_auth(auth_key.as_slice())
        .expect("device auth failed");
    Ok(device)
}

pub fn get_or_create_test_app_1() -> Result<Box<dyn SkfApp>> {
    let dev = use_first_device()?;
    let list = dev.enumerate_app_name()?;
    if list.contains(&TEST_APP_NAME_1.to_string()) {
        return dev.open_app(TEST_APP_NAME_1);
    }
    let attr = AppAttr {
        admin_pin: TEST_ADMIN_PIN.to_string(),
        admin_pin_retry_count: 8,
        user_pin: TEST_USER_PIN.to_string(),
        user_pin_retry_count: 8,
        create_file_rights: FILE_PERM_EVERYONE,
    };
    let dev = use_first_device()?;
    dev.create_app(TEST_APP_NAME_1, &attr)
}

pub fn get_or_create_test_container_1() -> Result<Box<dyn SkfContainer>> {
    let app = get_or_create_test_app_1()?;
    let list = app.enumerate_container_name()?;
    if list.contains(&TEST_CONTAINER_NAME_1.to_string()) {
        return app.open_container(TEST_CONTAINER_NAME_1);
    }
    app.create_container(TEST_CONTAINER_NAME_1)
}
