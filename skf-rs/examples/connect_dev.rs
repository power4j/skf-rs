use skf_rs::{Engine, LibLoader};

fn main() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let manager = engine.device_manager().unwrap();
    let _ = manager.connect_selected(chose_first).unwrap();
}

fn chose_first(list: Vec<&str>) -> Option<&str> {
    let name = list[0];
    println!("connect to '{}'", name);
    Some(name)
}
