use skf_rs::CreateAppOption;
use std::time::Duration;
mod common;
use common::use_first_device;
use skf_rs::helper::describe_result;
#[test]
#[ignore]
fn get_info_test() {
    let dev = use_first_device().unwrap();
    let ret = dev.info();
    println!("result: {:?}", &ret);
    assert!(ret.is_ok());
}

#[test]
#[ignore]
fn set_lab_test() {
    let dev = use_first_device().unwrap();
    let ret = dev.set_label("AB012345678901234567890123456789");
    println!("result: {:?}", &ret);
    assert!(ret.is_ok());
}

#[test]
#[ignore]
fn lock_test() {
    let dev = use_first_device().unwrap();
    let ret = dev.lock(Some(Duration::from_millis(100)));
    println!("result of lock : {:?}", &ret);
    let ret = dev.unlock();
    println!("result of unlock : {:?}", &ret);
    assert!(ret.is_ok());
}

#[test]
#[ignore]
fn invoke_dev_auth() {
    let dev = use_first_device().unwrap();
    let auth_data = [0u8; 16];
    let ret = dev.device_auth(auth_data.as_slice());
    println!("result of device_auth : {:?}", &ret);
    assert!(ret.is_err());
}

#[test]
#[ignore]
fn invoke_change_auth_key() {
    let dev = use_first_device().unwrap();
    let auth_key = [0u8; 16];
    let ret = dev.change_device_auth_key(auth_key.as_slice());
    println!("result of change_device_auth_key : {:?}", &ret);
    assert!(ret.is_err());
}

#[test]
#[ignore]
fn invoke_app_ctl() {
    let dev = use_first_device().unwrap();
    let ret = dev.enumerate_app_name();
    println!("result of enum_app : {:?}", &ret);
    assert!(ret.is_ok());

    let opt = CreateAppOption::default();
    let ret = dev.create_app(&opt);
    println!("result of create_app : {:?}", describe_result(&ret));
    assert!(ret.is_err());

    let ret = dev.open_app("NOT_EXISTS");
    println!("result of open_app: {:?}", describe_result(&ret));
    assert!(ret.is_err());

    let ret = dev.delete_app("NOT_EXISTS");
    println!("result of delete_app : {:?}", describe_result(&ret));
    assert!(ret.is_err());
}
