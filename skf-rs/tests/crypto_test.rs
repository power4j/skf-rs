mod common;
use crate::common::{use_crypto, use_first_device};
use skf_rs::helper::describe_result;
use skf_rs::{BlockCipherParameter, CryptoAlgorithm};

#[test]
#[ignore]
fn set_symmetric_key_test() {
    let dev = use_first_device().unwrap();
    let ret = dev.set_symmetric_key(CryptoAlgorithm::SgdSms4Ecb.id(), &[0u8; 16]);
    println!("set_symmetric_key result: {:?}", describe_result(&ret));
    assert!(ret.is_ok());
}

#[test]
#[ignore]
fn sms_4ecb_test() {
    let dev = use_first_device().unwrap();
    let crypto = use_crypto().unwrap();
    let key = dev
        .set_symmetric_key(CryptoAlgorithm::SgdSms4Ecb.id(), &[0u8; 16])
        .unwrap();
    crypto
        .encrypt_init(key.as_ref(), &BlockCipherParameter::default())
        .expect("encrypt_init failed");
    let input = [0u8; 16];
    println!("SgdSms4Ecb encrypt,input: {:?}", &input);
    let ret = crypto.encrypt(key.as_ref(), &input, 32);
    assert!(ret.is_ok());
    println!("SgdSms4Ecb encrypt,output: {:?}", &ret.unwrap());
}
