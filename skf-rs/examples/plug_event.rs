use skf_rs::{Engine, LibLoader};
use std::sync::Arc;
use std::thread;

fn main() {
    let seconds = 10;
    let timeout = std::time::Duration::from_secs(seconds);
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let ctl = engine.skf_ctl_arc().unwrap();
    let ctl_clone = Arc::clone(&ctl);
    let _ = thread::spawn(move || {
        thread::sleep(timeout);
        let ret = ctl_clone.cancel_wait_plug_event();
        println!("cancel wait plug event : {:?}", &ret);
        assert!(ret.is_ok());
    });
    println!("wait {} seconds for plug event ...", seconds);
    let evt = ctl.wait_plug_event().unwrap();
    match evt {
        None => {
            println!("No event");
        }
        Some(ref evt) => {
            println!("{} {}", evt.event_description(), evt.device_name,)
        }
    }
}
