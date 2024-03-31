use skf_rs::helper::auth::encrypt_auth_key_sm1_ecb;
use skf_rs::helper::easy::{recreate_app, recreate_container};
use skf_rs::spec::algorithm::{SGD_SM1_ECB, SGD_SM2_1};
use skf_rs::{
    AppAttr, BlockCipherParameter, Engine, LibLoader, SkfApp, SkfContainer, SkfDevice,
    FILE_PERM_EVERYONE, PIN_TYPE_USER,
};
use std::ops::Deref;

pub const APP_NAME: &str = "skf-app-demo";
pub const PIN: &str = "12345678";
pub const REQ_CONTAINER: &str = "test-agreement-1";
pub const RSP_CONTAINER: &str = "test-agreement-2";
pub const RESPONDER_ID: &[u8] = b"server";
pub const INITIATOR_ID: &[u8] = b"client";
pub const AUTH_KEY: [u8; 16] = [
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
];

pub fn main() {
    let (device, app) = setup_app();
    let (initiator, responder) = setup_container(app.deref());

    let initiator_pub_key = initiator.ecc_gen_key_pair(SGD_SM2_1).unwrap();
    let responder_pub_key = responder.ecc_gen_key_pair(SGD_SM2_1).unwrap();

    let sk_alg = SGD_SM1_ECB;
    let stage1 = initiator
        .sk_gen_agreement_data(sk_alg, INITIATOR_ID)
        .unwrap();
    let stage2 = responder
        .sk_gen_agreement_data_and_key(
            sk_alg,
            &initiator_pub_key,
            &stage1.0,
            INITIATOR_ID,
            RESPONDER_ID,
        )
        .unwrap();
    let stage3 = device
        .ecc_gen_session_key(
            stage1.1.as_ref(),
            &responder_pub_key,
            &stage2.0,
            RESPONDER_ID,
        )
        .unwrap();
    let crypto = device.block_cipher().unwrap();

    let plain = b"hello world";
    let cipher_param = BlockCipherParameter {
        iv: vec![],
        padding_type: 1,
        feed_bit_len: 0,
    };
    let initiator_sk = stage3.as_ref();
    crypto.encrypt_init(initiator_sk, &cipher_param).unwrap();
    let enc = crypto
        .encrypt(initiator_sk, plain, plain.len() * 2)
        .unwrap();

    println!("plain: {:?}", hex::encode(plain).as_str());
    println!(
        "initiator sk encrypt result: {:?}",
        hex::encode(&enc).as_str()
    );

    let responder_sk = stage2.1.as_ref();
    crypto.decrypt_init(responder_sk, &cipher_param).unwrap();
    let dec = crypto.decrypt(responder_sk, &enc, enc.len() * 2).unwrap();

    println!(
        "responder sk decrypt result: {:?}",
        hex::encode(dec).as_str()
    );
}
fn setup_app() -> (Box<dyn SkfDevice>, Box<dyn SkfApp>) {
    let device = Engine::new(LibLoader::env_lookup().expect("SKF Lib not load"))
        .device_manager()
        .and_then(|mgr| mgr.connect_selected(|list| Some(list[0])))
        .expect("Open device failed");
    let auth_key =
        encrypt_auth_key_sm1_ecb(device.as_ref(), &AUTH_KEY).expect("auth key encrypt failed");
    device
        .device_auth(auth_key.as_slice())
        .expect("device auth failed");

    let app = recreate_app(device.as_ref(), APP_NAME, app_attr).expect("create app failed");
    app.verify_pin(PIN_TYPE_USER, PIN)
        .expect("verify pin failed");
    (device, app)
}
fn app_attr() -> AppAttr {
    AppAttr {
        admin_pin: PIN.to_string(),
        admin_pin_retry_count: 8,
        user_pin: PIN.to_string(),
        user_pin_retry_count: 8,
        create_file_rights: FILE_PERM_EVERYONE,
    }
}
fn setup_container(app: &dyn SkfApp) -> (Box<dyn SkfContainer>, Box<dyn SkfContainer>) {
    let initiator =
        recreate_container(app, REQ_CONTAINER).expect("create initiator container failed");
    let responder =
        recreate_container(app, RSP_CONTAINER).expect("create responder container failed");
    (initiator, responder)
}
