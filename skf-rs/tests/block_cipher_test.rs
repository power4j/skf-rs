mod common;
use crate::common::{describe_result, use_block_cipher, use_first_device};
use skf_rs::spec::algorithm;
use skf_rs::BlockCipherParameter;

#[test]
#[ignore]
fn set_symmetric_key_test() {
    let dev = use_first_device();
    let ret = dev.set_symmetric_key(algorithm::SGD_SM4_ECB, &[0u8; 16]);
    println!("set_symmetric_key result: {:?}", describe_result(&ret));
    assert!(ret.is_ok());
}

#[test]
#[ignore]
fn sm4_ecb_test() {
    let param = BlockCipherParameter::default();
    let dev = use_first_device();
    let crypto = use_block_cipher();
    let key_handle = dev
        .set_symmetric_key(algorithm::SGD_SM4_ECB, &[0u8; 16])
        .unwrap();
    crypto
        .encrypt_init(key_handle.as_ref(), &param)
        .expect("encrypt_init failed");
    let input = [0u8; 16];
    println!("SgdSms4Ecb encrypt,input: {:?}", &input);

    let ret = crypto.encrypt(key_handle.as_ref(), &input, 32);
    assert!(&ret.is_ok());
    let encrypted = ret.unwrap();
    println!("SgdSms4Ecb encrypt,output: {:?}", encrypted);

    crypto
        .decrypt_init(key_handle.as_ref(), &param)
        .expect("decrypt_init failed");
    let ret = crypto.decrypt(key_handle.as_ref(), &encrypted, 32);
    assert!(ret.is_ok());
    let decrypted = ret.unwrap();
    println!("SgdSms4Ecb decrypt,output: {:?}", &decrypted);
    assert_eq!(&decrypted, &input);
}

#[test]
#[ignore]
fn sm4_ecb_group_test() {
    let param = BlockCipherParameter {
        iv: vec![],
        padding_type: 1,
        feed_bit_len: 0,
    };
    let dev = use_first_device();
    let crypto = use_block_cipher();
    let key_handle = dev
        .set_symmetric_key(algorithm::SGD_SM4_ECB, &[0u8; 16])
        .unwrap();
    crypto
        .encrypt_init(key_handle.as_ref(), &param)
        .expect("encrypt_init failed");
    let input = [0u8; 27];
    println!(
        "SgdSms4Ecb encrypt_update,input {} bytes :{:?}",
        &input.len(),
        &input
    );

    let ret = crypto.encrypt_update(key_handle.as_ref(), &input[0..16], 32);
    assert!(&ret.is_ok());
    let encrypted_1 = ret.unwrap();
    println!(
        "SgdSms4Ecb encrypt_update 1,output {} bytes: {:?}",
        &encrypted_1.len(),
        &encrypted_1
    );

    let ret = crypto.encrypt_update(key_handle.as_ref(), &input[16..27], 32);
    assert!(&ret.is_ok());
    let encrypted_2 = ret.unwrap();
    println!(
        "SgdSms4Ecb encrypt_update 2,output {} bytes: {:?}",
        &encrypted_2.len(),
        &encrypted_2
    );

    let ret = crypto.encrypt_final(key_handle.as_ref(), 32);
    assert!(&ret.is_ok());
    let encrypted_3 = ret.unwrap();
    println!(
        "SgdSms4Ecb encrypt_final,output {} bytes :{:?}",
        &encrypted_3.len(),
        &encrypted_3
    );

    let encrypted = [encrypted_1, encrypted_2, encrypted_3].concat();
    println!(
        "SgdSms4Ecb encrypt ,output {} bytes :{:?}",
        &encrypted.len(),
        &encrypted
    );

    crypto
        .decrypt_init(key_handle.as_ref(), &param)
        .expect("decrypt_init failed");

    let ret = crypto.decrypt_update(key_handle.as_ref(), &encrypted[0..16], 32);
    assert!(&ret.is_ok());
    let decrypted_1 = ret.unwrap();
    println!(
        "SgdSms4Ecb decrypt_update 1,output {} bytes: {:?}",
        &decrypted_1.len(),
        &decrypted_1
    );

    let ret = crypto.decrypt_update(key_handle.as_ref(), &encrypted[16..32], 32);
    assert!(&ret.is_ok());
    let decrypted_2 = ret.unwrap();
    println!(
        "SgdSms4Ecb decrypt_update 2,output {} bytes: {:?}",
        &decrypted_2.len(),
        &decrypted_2
    );

    let ret = crypto.decrypt_final(key_handle.as_ref(), 32);
    assert!(&ret.is_ok());
    let decrypted_3 = ret.unwrap();
    println!(
        "SgdSms4Ecb decrypt_final,output {} bytes: {:?}",
        &decrypted_3.len(),
        &decrypted_3
    );

    let decrypted = [decrypted_1, decrypted_2, decrypted_3].concat();
    println!(
        "SgdSms4Ecb decrypt,output {} bytes: {:?}",
        &decrypted.len(),
        &decrypted
    );
    assert_eq!(&decrypted, &input);
}
