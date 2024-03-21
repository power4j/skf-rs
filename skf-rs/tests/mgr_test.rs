use skf_rs::{Engine, LibLoader};
use std::sync::Arc;
use std::thread;

mod common;
use crate::common::describe_result;
use common::chose_first;

#[test]
#[ignore]
fn enum_device_test() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let manager = engine.device_manager().unwrap();
    let ret = manager.enumerate_device_name(true);
    println!("result: {:?}", &ret);
    assert!(ret.is_ok());
}

#[test]
#[ignore]
fn device_state_test() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let manager = engine.device_manager().unwrap();
    let ret = manager.device_state("xx");
    println!("result: {:?}", &ret);
    assert!(ret.is_ok());
}
#[test]
#[ignore]
fn connect_test() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let manager = engine.device_manager().unwrap();
    let ret = manager.connect("xx");
    println!("result: {:?}", describe_result(&ret));
    assert!(ret.is_err());
}

#[test]
#[ignore]
fn connect_selector_test() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let manager = engine.device_manager().unwrap();
    let ret = manager.connect_selected(chose_first);
    println!("result: {:?}", describe_result(&ret));
    assert!(ret.is_ok());
}

#[test]
#[ignore]
fn plug_event_test() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let manager = engine.device_manager_arc().unwrap();
    let manager_clone = Arc::clone(&manager);
    let _ = thread::spawn(move || {
        thread::sleep(std::time::Duration::from_secs(2));
        let ret = manager_clone.cancel_wait_plug_event();
        println!("cancel_wait_plug_event result: {:?}", &ret);
        assert!(ret.is_ok());
    });
    let ret = manager.wait_plug_event();
    println!("wait_plug_event result: {:?}", &ret);
    assert!(ret.is_ok());
}
