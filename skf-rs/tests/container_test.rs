use skf_api::native::types::ECCPublicKeyBlob;
use skf_rs::spec::algorithm::SGD_SM4_ECB;
use skf_rs::EnvelopedKeyData;

use crate::common::{
    describe_result, get_or_create_test_container_1, SK_INITIATOR_ID, SK_RESPONDER_ID,
};

mod common;

#[test]
#[ignore]
fn invoke_container_fn() {
    let (_dev, _app, container) = get_or_create_test_container_1();

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
    let ret = container.ecc_gen_key_pair(SGD_SM4_ECB);
    println!(
        "invoke ecc_gen_key_pair result: {:?}",
        describe_result(&ret)
    );

    let ret = container.ecc_import_key_pair(&EnvelopedKeyData::default());
    println!(
        "invoke ecc_import_key_pair result: {:?}",
        describe_result(&ret)
    );

    let ret = container.ecc_export_public_key(true);
    println!(
        "invoke ecc_export_public_key result: {:?}",
        describe_result(&ret)
    );

    let ret = container.ecc_sign(&[0u8; 32]);
    println!("invoke ecc_sign result: {:?}", describe_result(&ret));

    let ret = container.sk_gen_agreement_data(SGD_SM4_ECB, &SK_INITIATOR_ID);
    println!(
        "invoke sk_gen_agreement_data result: {:?}",
        describe_result(&ret)
    );

    let ret = container.sk_gen_agreement_data_and_key(
        SGD_SM4_ECB,
        &ECCPublicKeyBlob::default(),
        &ECCPublicKeyBlob::default(),
        &SK_INITIATOR_ID,
        &SK_RESPONDER_ID,
    );
    println!(
        "invoke sk_gen_agreement_data_and_key result: {:?}",
        describe_result(&ret)
    );

    let ret = container.sk_import(SGD_SM4_ECB, &[0u8; 32]);
    println!("invoke sk_import result: {:?}", describe_result(&ret));

    let ret = container.sk_export(SGD_SM4_ECB, &ECCPublicKeyBlob::default());
    println!("invoke sk_export result: {:?}", describe_result(&ret));
}
