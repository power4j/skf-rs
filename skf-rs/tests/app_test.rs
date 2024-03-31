mod common;

use crate::common::{
    describe_result, get_or_create_test_app_1, verify_admin_pin, verify_user_pin, TEST_ADMIN_PIN,
    TEST_FILE_NAME_1, TEST_USER_PIN,
};
use skf_rs::{FileAttr, FILE_PERM_EVERYONE, PIN_TYPE_USER};

#[test]
#[ignore]
fn invoke_app_security_fn() {
    let (_dev, app) = get_or_create_test_app_1();

    let ret = app.pin_info(PIN_TYPE_USER);
    println!("pin_info result: {:?}", &ret);

    let ret = app.change_pin(PIN_TYPE_USER, TEST_USER_PIN, TEST_USER_PIN);
    println!("change_pin result: {:?}", &ret);

    let ret = app.verify_pin(PIN_TYPE_USER, TEST_USER_PIN);
    println!("verify_pin result: {:?}", &ret);

    let ret = app.unblock_pin(TEST_ADMIN_PIN, TEST_USER_PIN);
    println!("unblock_pin result: {:?}", &ret);

    let ret = app.clear_secure_state();
    println!("clear_secure_state result: {:?}", &ret);
}

#[test]
#[ignore]
fn invoke_file_manager_fn() {
    let (_dev, app) = get_or_create_test_app_1();

    let ret = app.enumerate_file_name();
    println!("invoke enumerate_file_name result: {:?}", &ret);

    let ret = app.create_file(&FileAttr::default());
    println!("invoke create_file result: {:?}", &ret);

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
fn container_ctl_test() {
    let (_dev, app) = get_or_create_test_app_1();

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
fn file_ctl_test() {
    const FILE_SIZE: usize = 32;
    const FILE_NAME: &str = TEST_FILE_NAME_1;
    const WRITE_RIGHTS: u32 = FILE_PERM_EVERYONE;
    const READ_RIGHTS: u32 = FILE_PERM_EVERYONE;
    let (_dev, app) = get_or_create_test_app_1();

    let ret = verify_admin_pin(app.as_ref());
    println!("verify_admin_pin result: {:?}", &ret);

    let ret = app.enumerate_file_name();
    println!("enumerate_file_name result: {:?}", &ret);
    assert!(&ret.is_ok());

    let attr = FileAttr::builder()
        .file_size(FILE_SIZE)
        .file_name(FILE_NAME)
        .write_rights(WRITE_RIGHTS)
        .read_rights(READ_RIGHTS)
        .build();
    let ret = app.create_file(&attr);
    println!("create_file result: {:?}", &ret);
    assert!(&ret.is_ok());

    let ret = app.get_file_info(FILE_NAME);
    println!("get_file_info result: {:?}", &ret);
    assert!(&ret.is_ok());
    let info = ret.unwrap();
    assert_eq!(
        FILE_NAME,
        info.file_name.as_str(),
        "file name is not equal!"
    );
    assert_eq!(FILE_SIZE, info.file_size, "file size is not equal!");
    assert_eq!(READ_RIGHTS, info.read_rights, "read_rights is not equal!");
    assert_eq!(
        WRITE_RIGHTS, info.write_rights,
        "write_rights is not equal!"
    );

    let ret = app.write_file(FILE_NAME, 0, &[0x31u8; FILE_SIZE]);
    println!("write_file result: {:?}", &ret);
    assert!(&ret.is_ok());

    let ret = app.read_file(FILE_NAME, 0, FILE_SIZE);
    println!("read_file result: {:?}", &ret);
    assert!(&ret.is_ok());
    assert_eq!(
        &[0x31u8; FILE_SIZE],
        ret.unwrap().as_slice(),
        "file content is not equal!"
    );

    let ret = app.delete_file(FILE_NAME);
    println!("delete_file result: {:?}", &ret);
    assert!(&ret.is_ok());
}
