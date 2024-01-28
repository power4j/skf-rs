mod common;

use crate::common::{get_or_create_test_app_1, TEST_USER_PIN};
use skf_rs::PIN_TYPE_USER;

#[test]
#[ignore]
fn invoke_change_pin() {
    let app = get_or_create_test_app_1().unwrap();
    let ret = app.change_pin(PIN_TYPE_USER, TEST_USER_PIN, TEST_USER_PIN);
    println!("change_pin result: {:?}", &ret);
    assert!(ret.is_ok());
}
