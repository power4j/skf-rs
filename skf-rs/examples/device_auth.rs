use skf_rs::helper::auth::encrypt_auth_key_sm1_ecb;
use skf_rs::{Engine, LibLoader};

fn main() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let manager = engine.device_manager().unwrap();
    let device = manager
        .connect_selected(|list| Some(list[0]))
        .unwrap()
        .unwrap();
    let auth_key = encrypt_auth_key_sm1_ecb(
        device.as_ref(),
        &[
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
            0x37, 0x38,
        ],
    )
    .unwrap();
    let ret = device.device_auth(auth_key.as_slice());
    println!("device auth result: {:?}", ret);
}
