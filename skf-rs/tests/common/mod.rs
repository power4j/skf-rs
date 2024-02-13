use skf_api::native::error::SAR_APPLICATION_NOT_EXISTS;
use skf_rs::helper::auth::encrypt_auth_key_sm1_ecb;
use skf_rs::{
    AppAttr, DeviceManager, Engine, Error, LibLoader, Result, SkfApp, SkfContainer, SkfCrypto,
    SkfDevice, FILE_PERM_EVERYONE, PIN_TYPE_ADMIN, PIN_TYPE_USER,
};

pub const TEST_APP_NAME_1: &str = "skf-rs-test-app-1";
pub const TEST_ADMIN_PIN: &str = "12345678";
pub const TEST_USER_PIN: &str = "87654321";
pub const TEST_FILE_NAME_1: &str = "skf-rs-test-file-1";
pub const TEST_CONTAINER_NAME_1: &str = "skf-rs-test-container-1";
pub const TEST_AUTH_KEY: [u8; 16] = [
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
];

pub fn chose_first(list: Vec<&str>) -> Option<&str> {
    Some(list[0])
}

pub fn get_engine() -> Engine {
    let lib = LibLoader::env_lookup().expect("SKF Lib not load");
    Engine::new(lib)
}
pub fn device_manager() -> Box<dyn DeviceManager + Send + Sync> {
    get_engine()
        .device_manager()
        .expect("Cannot get device manager")
}
pub fn use_crypto() -> Box<dyn SkfCrypto + Send + Sync> {
    get_engine().crypto().expect("Cannot get Crypto service")
}
pub fn use_first_device() -> Box<dyn SkfDevice> {
    let manager = device_manager();
    manager
        .connect_selected(chose_first)
        .expect("SKF Device not found")
        .unwrap()
}

pub fn use_first_device_with_auth() -> Box<dyn SkfDevice> {
    let device = use_first_device();
    let auth_key =
        encrypt_auth_key_sm1_ecb(device.as_ref(), &TEST_AUTH_KEY).expect("auth key encrypt failed");
    let _ = device
        .device_auth(auth_key.as_slice())
        .expect("device auth failed");
    device
}

pub fn get_or_create_test_app_1() -> (Box<dyn SkfDevice>, Box<dyn SkfApp>) {
    let dev = use_first_device_with_auth();
    let list = dev
        .enumerate_app_name()
        .expect("enumerate application fail");
    if list.contains(&TEST_APP_NAME_1.to_string()) {
        println!("going to open app: {}", TEST_APP_NAME_1);
        let app = dev
            .open_app(TEST_APP_NAME_1)
            .expect("Open application fail");
        let _ = app.clear_secure_state();
        return (dev, app);
    }
    println!("going to create app: {}", TEST_APP_NAME_1);
    let attr = AppAttr {
        admin_pin: TEST_ADMIN_PIN.to_string(),
        admin_pin_retry_count: 8,
        user_pin: TEST_USER_PIN.to_string(),
        user_pin_retry_count: 8,
        create_file_rights: FILE_PERM_EVERYONE,
    };
    let app = dev
        .create_app(TEST_APP_NAME_1, &attr)
        .expect("Create application fail");
    let _ = app.clear_secure_state();
    (dev, app)
}

pub fn get_or_create_test_container_1(
) -> (Box<dyn SkfDevice>, Box<dyn SkfApp>, Box<dyn SkfContainer>) {
    let (dev, app) = get_or_create_test_app_1();
    verify_admin_pin(app.as_ref()).expect("Verify admin pin fail");
    let list = app
        .enumerate_container_name()
        .expect("enumerate container fail");
    if list.contains(&TEST_CONTAINER_NAME_1.to_string()) {
        println!("going to open container: {}", TEST_CONTAINER_NAME_1);
        let container = app
            .open_container(TEST_CONTAINER_NAME_1)
            .expect("open container fail");
        return (dev, app, container);
    }
    println!("going to create container: {}", TEST_CONTAINER_NAME_1);
    let container = app
        .create_container(TEST_CONTAINER_NAME_1)
        .expect("Create container fail");
    (dev, app, container)
}

pub fn verify_admin_pin(app: &dyn SkfApp) -> Result<()> {
    app.verify_pin(PIN_TYPE_ADMIN, &TEST_ADMIN_PIN)
}

pub fn verify_user_pin(app: &dyn SkfApp) -> Result<()> {
    app.verify_pin(PIN_TYPE_USER, &TEST_USER_PIN)
}
