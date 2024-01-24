use skf_rs::{Engine, LibLoader};
use std::sync::Arc;
use std::thread;

mod common;
use common::chose_first;
#[test]
#[ignore]
fn enum_device_test() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let ctl = engine.skf_ctl().unwrap();
    let ret = ctl.enum_device(true);
    println!("result: {:?}", &ret);
    assert!(ret.is_ok());
}

#[test]
#[ignore]
fn device_state_test() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let ctl = engine.skf_ctl().unwrap();
    let ret = ctl.device_state("xx");
    println!("result: {:?}", &ret);
    assert!(ret.is_ok());
}
#[test]
#[ignore]
fn connect_test() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let ctl = engine.skf_ctl().unwrap();
    let ret = ctl.connect("xx");
    assert!(ret.is_err());
}

#[test]
#[ignore]
fn connect_selector_test() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let ctl = engine.skf_ctl().unwrap();
    let ret = ctl.connect_selected(chose_first);
    assert!(ret.is_ok());
}

#[test]
#[ignore]
fn plug_event_test() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let ctl = engine.skf_ctl_arc().unwrap();
    let ctl_clone = Arc::clone(&ctl);
    let _ = thread::spawn(move || {
        thread::sleep(std::time::Duration::from_secs(5));
        let ret = ctl_clone.cancel_wait_plug_event();
        println!("cancel_wait_plug_event result: {:?}", &ret);
        assert!(ret.is_ok());
    });
    let ret = ctl.wait_plug_event();
    println!("wait_plug_event result: {:?}", &ret);
    assert!(ret.is_ok());
}