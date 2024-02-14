use skf_rs::{Engine, LibLoader};
use std::sync::Arc;
use std::thread;

fn main() {
    let seconds = 10;
    let timeout = std::time::Duration::from_secs(seconds);
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let manager = engine.device_manager_arc().unwrap();
    let manager_clone = Arc::clone(&manager);
    let _ = thread::spawn(move || {
        thread::sleep(timeout);
        let ret = manager_clone.cancel_wait_plug_event();
        println!("cancel wait plug event : {:?}", &ret);
        assert!(ret.is_ok());
    });
    println!("wait {} seconds for plug event ...", seconds);
    let evt = manager.wait_plug_event().unwrap();
    match evt {
        None => {
            println!("No event");
        }
        Some(ref evt) => {
            println!("{} {}", evt.event_description(), evt.device_name,)
        }
    }
}
