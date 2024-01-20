use skf_rs::{Engine, LibLoader};
use std::time::Duration;
mod common;
use common::chose_first;
#[test]
#[ignore]
fn get_info_test() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let ctl = engine.skf_ctl().unwrap();
    let dev = ctl.connect_selected(chose_first).unwrap().unwrap();
    let ret = dev.info();
    println!("result: {:?}", &ret);
    assert!(ret.is_ok());
}

#[test]
#[ignore]
fn set_lab_test() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let ctl = engine.skf_ctl().unwrap();
    let dev = ctl.connect_selected(chose_first).unwrap().unwrap();
    let ret = dev.set_label("AB012345678901234567890123456789");
    println!("result: {:?}", &ret);
    assert!(ret.is_ok());
}

#[test]
#[ignore]
fn lock_test() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let ctl = engine.skf_ctl().unwrap();
    let dev = ctl.connect_selected(chose_first).unwrap().unwrap();
    let ret = dev.lock(Some(Duration::from_millis(100)));
    println!("result of lock : {:?}", &ret);
    let ret = dev.unlock();
    println!("result of unlock : {:?}", &ret);
    assert!(ret.is_ok());
}
