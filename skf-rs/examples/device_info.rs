use skf_rs::{Engine, LibLoader};

fn main() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let manager = engine.device_manager().unwrap();
    let device = manager.connect_selected(|list| Some(list[0])).unwrap();
    let info = device.info().unwrap();

    println!("device info '{:?}'", &info);
}
