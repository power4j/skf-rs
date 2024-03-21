use skf_api::native::types::{ECCPrivateKeyBlob, ECCPublicKeyBlob};
use skf_rs::helper::auth::encrypt_auth_key_sm1_ecb;
use skf_rs::helper::easy::{open_or_create_app, open_or_create_container};
use skf_rs::spec::algorithm::{SGD_SM1_ECB, SGD_SM2_1, SGD_SM4_ECB};
use skf_rs::{
    AppAttr, BlockCipherParameter, Engine, LibLoader, SkfApp, SkfContainer, SkfDevice,
    FILE_PERM_EVERYONE, PIN_TYPE_USER,
};
use std::path::PathBuf;

pub const APP_NAME: &str = "skf-app-demo";
pub const PIN: &str = "12345678";
pub const REQ_CONTAINER: &str = "demo-container-1";
pub const RSP_CONTAINER: &str = "demo-container-2";
pub const RESPONDER_ID: &[u8] = b"server";
pub const INITIATOR_ID: &[u8] = b"client";
pub const AUTH_KEY: [u8; 16] = [
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
];
// todo : remove
const CER_DATA: &str ="30820323308202d0a00302010202086bb2c39d0e347fa8300a06082a811c81450183753081843112301006035504030c09e6a0b9e8af81e4b9a6311a301806092a864886f70d010901160b313633403136332e636f6d310c300a060355040b0c03706b69310f300d060355040a0c06e6b894e7bf813112301006035504070c09e6b58ee58d97e5b8823112301006035504080c09e5b1b1e4b89ce79c81310b300906035504061302434e301e170d3131303431373136303030305a170d3135303431373136303030305a30818a3118301606035504030c0fe7aea1e79086e59198e8af81e4b9a6311a301806092a864886f70d010901160b313633403136332e636f6d310c300a060355040b0c03706b69310f300d060355040a0c06e6b894e7bf813112301006035504070c09e6b58ee58d97e5b8823112301006035504080c09e5b1b1e4b89ce79c81310b300906035504061302434e308201143081cd06082a811c814501822d3081c0020101302b06072a8648ce3d01010220010001000000000000000000000000000000000000000000000000000402030130440420000000000000000000000000000000000000000000000000000000000000370004200000000000000000000000000000000000000000000000000000000000000c010441040000000000000000000000000000000000000000000000000000000000000c0100000000000000000000000000000000000000000000000000000000000037000202370002010b0342000492f27ec67ea52a2a717977a27564426ea4667a5297bfeb9dc2dcaadf97537b42131a3db5f1df851b113773a094f1f26b3ec785eeedac71cc326e46f1e3b2bbdea3673065300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070302301d0603551d0e041604143d472d2649229db24f1bafbc3f7ac35a70d99c71301f0603551d2304183016801483e0cacd68987ba08162f261d6204250c4fad1e7300a06082a811c81450183750341002e954338485a180b1ee8a9d83ce1bb574228641d4fcd6220ce1ec9cfded0a4b48cb021e1b50eeb92774de07dfe0a1b9f692d8064673716f9a8de9c95ad7b8065";

pub fn main() {
    let x = std::fs::read(PathBuf::from(
        "D:\\runtime\\u-key\\fisec.cn\\extra\\国标\\windows64\\ECC.cer",
    ))
    .unwrap();
    println!("{}", hex::encode(&x));
    let (device, app) = setup_app();
    let (initiator, responder) = setup_container(&app);
    //let initiator_key_pair = ecc_key_pair();
    //let responder_key_pair = ecc_key_pair();
    let initiator_pub_key = initiator.ecc_gen_key_pair(SGD_SM2_1).unwrap();
    let responder_pub_key = responder.ecc_gen_key_pair(SGD_SM2_1).unwrap();
    let stage1 = initiator
        .sk_gen_agreement_data(SGD_SM1_ECB, INITIATOR_ID)
        .unwrap();
    let stage2 = responder
        .sk_gen_agreement_data_and_key(
            SGD_SM4_ECB,
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
    let enc = crypto.encrypt(initiator_sk, plain, 32).unwrap();

    println!("initiator sk encrypt result: {:?}", enc);

    let responder_sk = stage2.1.as_ref();
    crypto.decrypt_init(responder_sk, &cipher_param).unwrap();
    let dec = crypto.decrypt(responder_sk, &enc, 32).unwrap();

    println!("responder sk decrypt result: {:?}", dec);
}
fn setup_app() -> (Box<dyn SkfDevice>, Box<dyn SkfApp>) {
    let device = Engine::new(LibLoader::env_lookup().expect("SKF Lib not load"))
        .device_manager()
        .and_then(|mgr| mgr.connect_selected(|list| Some(list[0])))
        .expect("Open device failed");
    let auth_key =
        encrypt_auth_key_sm1_ecb(device.as_ref(), &AUTH_KEY).expect("auth key encrypt failed");
    let _ = device
        .device_auth(auth_key.as_slice())
        .expect("device auth failed");

    let app =
        open_or_create_app(device.as_ref(), APP_NAME, app_attr).expect("open or create app failed");
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
fn setup_container(app: &Box<dyn SkfApp>) -> (Box<dyn SkfContainer>, Box<dyn SkfContainer>) {
    let initiator = open_or_create_container(app.as_ref(), REQ_CONTAINER)
        .expect("open initiator container failed");
    let responder = open_or_create_container(app.as_ref(), RSP_CONTAINER)
        .expect("open responder container failed");
    (initiator, responder)
}

fn ecc_key_pair() -> (ECCPrivateKeyBlob, ECCPublicKeyBlob) {
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
