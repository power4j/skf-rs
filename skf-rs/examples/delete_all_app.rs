use skf_rs::helper::auth::encrypt_auth_key_sm1_ecb;
use skf_rs::{Engine, LibLoader};

pub const AUTH_KEY: [u8; 16] = [
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
];

fn main() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let manager = engine.device_manager().unwrap();
    let device = manager
        .connect_selected(|list| Some(list[0]))
        .unwrap()
        .unwrap();
    let auth_key = encrypt_auth_key_sm1_ecb(device.as_ref(), &AUTH_KEY).unwrap();
    let _ = device.device_auth(auth_key.as_slice());
    let app_list = device.enumerate_app_name().unwrap();
    if app_list.is_empty() {
        println!("no app to delete");
        return;
    }
    println!("app list to delete : {:?}", &app_list);
    for ref name in app_list {
        let ret = device.delete_app(&name);
        println!("result of delete app ({}): {:?}", name, ret);
    }
}
