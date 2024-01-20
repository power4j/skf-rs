use skf_rs::{Engine, LibLoader};

fn main() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let ctl = engine.skf_ctl().unwrap();
    let device = ctl.connect_selected(|list| Some(list[0])).unwrap().unwrap();
    let info = device.info().unwrap();

    println!("device info '{:?}'", &info);
}
