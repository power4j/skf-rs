mod common;

use crate::common::{
    get_or_create_test_app_1, get_or_create_test_container_1, verify_admin_pin, verify_user_pin,
    TEST_USER_PIN,
};
use skf_rs::helper::describe_result;
use skf_rs::{FileAttr, PIN_TYPE_USER};

#[test]
#[ignore]
fn invoke_app_security_fn() {
    let app = get_or_create_test_app_1().unwrap();

    let ret = app.pin_info(PIN_TYPE_USER);
    println!("pin_info result: {:?}", &ret);

    let ret = app.change_pin(PIN_TYPE_USER, TEST_USER_PIN, TEST_USER_PIN);
    println!("change_pin result: {:?}", &ret);

    let ret = app.verify_pin(PIN_TYPE_USER, TEST_USER_PIN);
    println!("verify_pin result: {:?}", &ret);

    let ret = app.pin_info(PIN_TYPE_USER);
    println!("pin_info result: {:?}", &ret);

    let ret = app.unblock_pin(TEST_USER_PIN, TEST_USER_PIN);
    println!("unblock_pin result: {:?}", &ret);

    let ret = app.clear_secure_state();
    println!("clear_secure_state result: {:?}", &ret);
}

#[test]
#[ignore]
fn invoke_file_manager_fn() {
    let app = get_or_create_test_app_1().unwrap();

    let ret = app.enumerate_file_name();
    println!("invoke enumerate_file_name result: {:?}", &ret);

    let ret = app.create_file(&FileAttr::default());
    println!("create_file result: {:?}", &ret);

    let ret = app.get_file_info("app-xxx");
    println!("invoke get_file_info result: {:?}", &ret);

    let ret = app.write_file("app-xxx", 0, &[0x31u8; 10]);
    println!("invoke write_file result: {:?}", &ret);

    let ret = app.read_file("app-xxx", 0, 10);
    println!("invoke read_file result: {:?}", &ret);

    let ret = app.delete_file("app-xxx");
    println!("invoke delete_file result: {:?}", &ret);
}

#[test]
#[ignore]
fn invoke_container_manager_fn() {
    let app = get_or_create_test_app_1().unwrap();

    let ret = verify_admin_pin(app.as_ref());
    println!("invoke verify_admin_pin result: {:?}", &ret);

    let ret = verify_user_pin(app.as_ref());
    println!("invoke verify_user_pin result: {:?}", &ret);

    let ret = app.enumerate_container_name();
    println!("invoke enumerate_file_name result: {:?}", &ret);

    let ret = app.create_container("container-xxx");
    println!(
        "invoke create_container result: {:?}",
        describe_result(&ret)
    );

    let ret = app.open_container("container-xxx");
    println!("invoke open_container result: {:?}", describe_result(&ret));

    let ret = app.delete_container("container-xxx");
    println!("invoke delete_container result: {:?}", &ret);
}

#[test]
#[ignore]
fn invoke_container_fn() {
    let container = get_or_create_test_container_1().unwrap();

    let ret = container.get_type();
    println!("invoke get_type result: {:?}", &ret);

    let ret = container.import_certificate(true, &[0u8; 256]);
    println!(
        "invoke import_certificate result: {:?}",
        describe_result(&ret)
    );

    let ret = container.export_certificate(true);
    println!(
        "invoke export_certificate result: {:?}",
        describe_result(&ret)
    );
}
