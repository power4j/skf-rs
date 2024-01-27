use skf_rs::{Engine, LibLoader};

fn main() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let manager = engine.device_manager().unwrap();
    let list = manager.enum_device(true).unwrap();
    list.iter().for_each(|name| println!("{}", name));
}
