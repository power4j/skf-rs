use skf_rs::{Engine, LibLoader};

fn main() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let ctl = engine.skf_ctl().unwrap();
    let list = ctl.enum_device(true).unwrap();
    list.iter().for_each(|name| println!("{}", name));
}
