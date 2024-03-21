use skf_api::native::types::{ECCPrivateKeyBlob, ECCPublicKeyBlob};
use skf_rs::helper::auth::encrypt_auth_key_sm1_ecb;
use skf_rs::{
    AppAttr, DeviceManager, Engine, LibLoader, Result, SkfApp, SkfBlockCipher, SkfContainer,
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
pub const SK_INITIATOR_ID: [u8; 32] = [1u8; 32];
pub const SK_RESPONDER_ID: [u8; 32] = [2u8; 32];

// todo : remove
pub const EC_CER_DATA: &str ="30820323308202d0a00302010202086bb2c39d0e347fa8300a06082a811c81450183753081843112301006035504030c09e6a0b9e8af81e4b9a6311a301806092a864886f70d010901160b313633403136332e636f6d310c300a060355040b0c03706b69310f300d060355040a0c06e6b894e7bf813112301006035504070c09e6b58ee58d97e5b8823112301006035504080c09e5b1b1e4b89ce79c81310b300906035504061302434e301e170d3131303431373136303030305a170d3135303431373136303030305a30818a3118301606035504030c0fe7aea1e79086e59198e8af81e4b9a6311a301806092a864886f70d010901160b313633403136332e636f6d310c300a060355040b0c03706b69310f300d060355040a0c06e6b894e7bf813112301006035504070c09e6b58ee58d97e5b8823112301006035504080c09e5b1b1e4b89ce79c81310b300906035504061302434e308201143081cd06082a811c814501822d3081c0020101302b06072a8648ce3d01010220010001000000000000000000000000000000000000000000000000000402030130440420000000000000000000000000000000000000000000000000000000000000370004200000000000000000000000000000000000000000000000000000000000000c010441040000000000000000000000000000000000000000000000000000000000000c0100000000000000000000000000000000000000000000000000000000000037000202370002010b0342000492f27ec67ea52a2a717977a27564426ea4667a5297bfeb9dc2dcaadf97537b42131a3db5f1df851b113773a094f1f26b3ec785eeedac71cc326e46f1e3b2bbdea3673065300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070302301d0603551d0e041604143d472d2649229db24f1bafbc3f7ac35a70d99c71301f0603551d2304183016801483e0cacd68987ba08162f261d6204250c4fad1e7300a06082a811c81450183750341002e954338485a180b1ee8a9d83ce1bb574228641d4fcd6220ce1ec9cfded0a4b48cb021e1b50eeb92774de07dfe0a1b9f692d8064673716f9a8de9c95ad7b8065";

pub fn describe_result<T>(result: &Result<T>) -> String {
    match result.as_ref() {
        Ok(_) => "OK".to_string(),
        Err(e) => format!("{:?}", e),
    }
}

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
pub fn use_block_cipher() -> Box<dyn SkfBlockCipher + Send + Sync> {
    get_engine()
        .block_cipher()
        .expect("Cannot get Crypto service")
}
pub fn use_first_device() -> Box<dyn SkfDevice> {
    let manager = device_manager();
    manager
        .connect_selected(chose_first)
        .expect("SKF Device not found")
}

pub fn use_first_device_with_auth() -> Box<dyn SkfDevice> {
    let device = use_first_device();
    let auth_key =
        encrypt_auth_key_sm1_ecb(device.as_ref(), &TEST_AUTH_KEY).expect("auth key encrypt failed");
    device
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
    app.verify_pin(PIN_TYPE_ADMIN, TEST_ADMIN_PIN)
}

pub fn verify_user_pin(app: &dyn SkfApp) -> Result<()> {
    app.verify_pin(PIN_TYPE_USER, TEST_USER_PIN)
}

pub fn ext_ecc_key_pair() -> (ECCPrivateKeyBlob, ECCPublicKeyBlob) {
    let x =
        hex::decode("9EF573019D9A03B16B0BE44FC8A5B4E8E098F56034C97B312282DD0B4810AFC3").unwrap();
    let y =
        hex::decode("CC759673ED0FC9B9DC7E6FA38F0E2B121E02654BF37EA6B63FAF2A0D6013EADF").unwrap();
    let key =
        hex::decode("FAB8BBE670FAE338C9E9382B9FB6485225C11A3ECB84C938F10F20A93B6215F0").unwrap();

    let public_key_blob = ECCPublicKeyBlob::new_256(&x[..], &y[..]);
    let private_key_blob = ECCPrivateKeyBlob::new_256(&key[..]);

    (private_key_blob, public_key_blob)
}
