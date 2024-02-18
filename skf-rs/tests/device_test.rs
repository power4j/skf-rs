use skf_rs::{AppAttr, FILE_PERM_EVERYONE};
use std::time::{Duration, SystemTime};
mod common;
use crate::common::{ext_ecc_key_pair, use_first_device_with_auth, TEST_ADMIN_PIN, TEST_USER_PIN};
use common::use_first_device;

use skf_rs::helper::describe_result;

#[test]
#[ignore]
fn get_info_test() {
    let dev = use_first_device();
    let ret = dev.info();
    println!("result: {:?}", &ret);
    assert!(ret.is_ok());
}

#[test]
#[ignore]
fn set_lab_test() {
    let dev = use_first_device();
    let ret = dev.set_label("AB012345678901234567890123456789");
    println!("result: {:?}", &ret);
    assert!(ret.is_ok());
}

#[test]
#[ignore]
fn lock_test() {
    let dev = use_first_device();
    let ret = dev.lock(Some(Duration::from_millis(100)));
    println!("result of lock : {:?}", &ret);
    let ret = dev.unlock();
    println!("result of unlock : {:?}", &ret);
    assert!(ret.is_ok());
}

#[test]
#[ignore]
fn invoke_transmit() {
    let dev = use_first_device();
    // fake cmd data
    let ret = dev.transmit([0u8; 16].as_slice(), 16);
    println!("invoke transmit : {:?}", &ret);
    assert!(ret.is_err());
}

#[test]
#[ignore]
fn gen_random_test() {
    let dev = use_first_device();
    let ret = dev.gen_random(8);
    println!("result of gen_random : {:?}", &ret);
    assert!(ret.is_ok());
}
#[test]
#[ignore]
fn invoke_dev_auth() {
    let dev = use_first_device();
    let auth_data = [0u8; 16];
    let ret = dev.device_auth(auth_data.as_slice());
    println!("invoke device_auth : {:?}", &ret);
}

#[test]
#[ignore]
fn invoke_change_auth_key() {
    let dev = use_first_device();
    let auth_key = [0u8; 16];
    let ret = dev.change_device_auth_key(auth_key.as_slice());
    println!("invoke change_device_auth_key : {:?}", &ret);
}

#[test]
#[ignore]
fn invoke_app_ctl() {
    let dev = use_first_device();
    let ret = dev.enumerate_app_name();
    println!("invoke enum_app : {:?}", &ret);

    let name = "SKF_APP_TEST";
    let ret = dev.create_app(name, &AppAttr::default());
    println!("invoke create_app : {:?}", describe_result(&ret));

    let ret = dev.open_app(name);
    println!("invoke open_app: {:?}", describe_result(&ret));

    let ret = dev.delete_app(name);
    println!("invoke delete_app : {:?}", describe_result(&ret));
}

#[test]
#[ignore]
fn app_ctl_test() {
    let app_name = format!(
        "TEST_{}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );

    let attr = AppAttr {
        admin_pin: TEST_ADMIN_PIN.to_string(),
        admin_pin_retry_count: 6,
        user_pin: TEST_USER_PIN.to_string(),
        user_pin_retry_count: 6,
        create_file_rights: FILE_PERM_EVERYONE,
    };

    let dev = use_first_device_with_auth();
    let ret = dev.enumerate_app_name();
    println!("result of enum_app : {:?}", &ret);
    assert!(ret.is_ok());

    let ret = dev.create_app(&app_name, &attr);
    println!("result of create_app : {:?}", describe_result(&ret));
    assert!(ret.is_ok());

    let ret = dev.open_app(&app_name);
    println!("result of open_app: {:?}", describe_result(&ret));
    assert!(ret.is_ok());

    let ret = dev.delete_app(&app_name);
    println!("result of delete_app : {:?}", describe_result(&ret));
    assert!(ret.is_ok());
}

#[test]
#[ignore]
fn ext_ecc_crypt_test() {
    let (private_key_blob, public_key_blob) = ext_ecc_key_pair();
    let plain = b"Hello World";
    let dev = use_first_device();
    let ret = dev.ext_ecc_encrypt(&public_key_blob, plain);
    println!("result of ext_ecc_encrypt : {:?}", &ret);
    assert!(ret.is_ok());
    let cipher = ret.unwrap();

    let ret = dev.ext_ecc_decrypt(&private_key_blob, &cipher);
    println!("result of ext_ecc_decrypt : {:?}", &ret);
    assert!(ret.is_ok());
    let plain2 = ret.unwrap();

    assert_eq!(plain, plain2.as_slice());
}

#[test]
#[ignore]
fn ext_ecc_sign_test() {
    let (private_key_blob, public_key_blob) = ext_ecc_key_pair();
    let plain = b"Hello World";
    let dev = use_first_device();
    let ret = dev.ext_ecc_sign(&private_key_blob, plain);
    println!("result of ext_ecc_sign : {:?}", &ret);
    assert!(ret.is_ok());
    let sign = ret.unwrap();
    let ret = dev.ext_ecc_verify(&public_key_blob, plain, &sign);
    println!("result of ext_ecc_verify : {:?}", &ret);
    assert!(ret.is_ok());
}
