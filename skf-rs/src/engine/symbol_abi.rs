use crate::{Engine, LibLoader, SkfDevice};
use skf_api::native::types::{Void, HANDLE};
use std::path::PathBuf;

const MOCK_DEV_HANDLE_VALUE: usize = 0xF1111111;
const MOCK_APP_HANDLE_VALUE: usize = 0xF2222222;
const MOCK_CONTAINER_HANDLE_VALUE: usize = 0xF3333333;
const MOCK_KEY_HANDLE_VALUE: usize = 0xF4444444;
const MOCK_HASH_KEY_HANDLE_VALUE: usize = 0xF5555555;
const MOCK_AGREEMENT_KEY_HANDLE_VALUE: usize = 0xF6666666;
const MOCK_MAC_KEY_HANDLE_VALUE: usize = 0xF8888888;

pub fn raw_handle(address_value: usize) -> HANDLE {
    let raw_ptr: *const Void = address_value as *const Void;
    raw_ptr
}

pub fn describe_result<T>(result: &crate::Result<T>) -> String {
    match result.as_ref() {
        Ok(_) => "OK".to_string(),
        Err(e) => format!("{:?}", e),
    }
}
fn get_stub_lib() -> PathBuf {
    let name = "skf_abi_stub";
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    let lib_file = if cfg!(target_os = "windows") {
        format!("{}.dll", name)
    } else if cfg!(target_os = "macos") {
        format!("lib{}.dylib", name)
    } else {
        format!("lib{}.so", name)
    };

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push(profile);
    path.push(&lib_file);

    if !path.exists() {
        // 尝试工作区路径
        let mut workspace_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        workspace_path.push("..");
        workspace_path.push("target");
        workspace_path.push(profile);
        workspace_path.push(&lib_file);
        if workspace_path.exists() {
            return workspace_path;
        }
        panic!("Stub library not found. Expected path: {}", path.display());
    }

    path
}

fn use_stub_engine() -> crate::Result<Engine> {
    let lib_file = get_stub_lib().display().to_string();
    LibLoader::of_library_file(lib_file).map(|lib| Engine::new(lib))
}

fn use_device() -> crate::Result<Box<dyn SkfDevice>> {
    let engine = use_stub_engine()?;
    let manager = engine.device_manager()?;
    manager.connect("any")
}

#[cfg(test)]
mod device_mgr_test {
    use super::*;

    #[test]
    fn enumerate_device_name_test() {
        let engine = use_stub_engine().unwrap();
        let manager = engine.device_manager().unwrap();
        let ret = manager.enumerate_device_name(false);
        println!("enumerate_device_name result: {:?}", &ret);
        assert!(ret.is_ok());
    }

    #[test]
    fn device_state_test() {
        let engine = use_stub_engine().unwrap();
        let manager = engine.device_manager().unwrap();
        let ret = manager.device_state("any");
        println!("device_state result: {:?}", &ret);
        assert!(ret.is_ok());
    }

    #[test]
    fn wait_plug_event_test() {
        let engine = use_stub_engine().unwrap();
        let manager = engine.device_manager().unwrap();
        let ret = manager.wait_plug_event();
        println!("wait_plug_event result: {:?}", &ret);
        assert!(ret.is_ok());
    }

    #[test]
    fn cancel_wait_plug_event_test() {
        let engine = use_stub_engine().unwrap();
        let manager = engine.device_manager().unwrap();
        let ret = manager.cancel_wait_plug_event();
        println!("cancel_wait_plug_event result: {:?}", &ret);
        assert!(ret.is_ok());
    }

    #[test]
    fn connect_test() {
        let engine = use_stub_engine().unwrap();
        let manager = engine.device_manager().unwrap();
        let ret = manager.connect("any");
        println!("connect result: {:?}", describe_result(&ret));
        assert!(ret.is_ok());
    }
}

#[cfg(test)]
mod device_ctl_test {
    use super::*;
    use std::time::Duration;

    #[test]
    fn set_label_test() {
        let ret = use_device().unwrap().set_label("any");
        println!("set_label result: {:?}", describe_result(&ret));
        assert!(ret.is_ok());
    }

    #[test]
    fn device_info_test() {
        let device = use_device().unwrap();
        let ret = device.info();
        println!("info result: {:?}", &ret);
        assert!(ret.is_ok());
    }

    #[test]
    fn device_lock_test() {
        let ret = use_device().unwrap().lock(Some(Duration::from_millis(1)));
        println!("lock(with timeout) result: {:?}", &ret);
        assert!(ret.is_ok());

        let ret = use_device().unwrap().lock(None);
        println!("lock(without timeout) result: {:?}", &ret);
        assert!(ret.is_ok());
    }

    #[test]
    fn device_unlock_test() {
        let ret = use_device().unwrap().unlock();
        println!("unlock result: {:?}", &ret);
        assert!(ret.is_ok());
    }

    #[test]
    fn transmit_test() {
        let cmd = vec![1u8];
        let ret = use_device().unwrap().transmit(&cmd, 64);
        println!("transmit result: {:?}", &ret);
        assert!(ret.is_ok());
    }
}

#[cfg(test)]
mod device_crypto_test {
    use super::*;
    use crate::{engine::crypto::ManagedKeyImpl, ECCEncryptedData};
    use skf_api::native::types::{ECCPrivateKeyBlob, ECCPublicKeyBlob, ECCSignatureBlob};

    #[test]
    fn gen_random_test() {
        let ret = use_device().unwrap().gen_random(32);
        println!("gen_random result: {:?}", describe_result(&ret));
        assert!(ret.is_ok());
    }

    #[test]
    fn set_symmetric_key_test() {
        let device = use_device().unwrap();
        let ret = device.set_symmetric_key(1, &vec![1u8]);
        println!("set_symmetric_key result: {:?}", describe_result(&ret));
        assert!(ret.is_ok());
    }

    #[test]
    fn ext_ecc_encrypt_test() {
        let pub_key = ECCPublicKeyBlob::default();
        let data = vec![1u8, 2u8];
        let ret = use_device().unwrap().ext_ecc_encrypt(&pub_key, &data);
        println!("ext_ecc_encrypt result: {:?}", &ret);
        assert!(ret.is_ok());
    }

    #[test]
    fn ext_ecc_decrypt_test() {
        let pri_key = ECCPrivateKeyBlob::default();
        let data = ECCEncryptedData {
            cipher: vec![1u8, 2u8],
            ec_x: [0u8; 64],
            ec_y: [0u8; 64],
            hash: [0u8; 32],
        };
        let ret = use_device().unwrap().ext_ecc_decrypt(&pri_key, &data);
        println!("ext_ecc_decrypt result: {:?}", &ret);
        assert!(ret.is_ok());
    }

    #[test]
    fn ext_ecc_sign_test() {
        let pri_key = ECCPrivateKeyBlob::default();
        let data = vec![1u8, 2u8];
        let ret = use_device().unwrap().ext_ecc_sign(&pri_key, &data);
        println!("ext_ecc_sign result: {:?}", &ret);
        assert!(ret.is_ok());
    }
    #[test]
    fn ext_ecc_verify_test() {
        let pub_key = ECCPublicKeyBlob::default();
        let sign = ECCSignatureBlob::default();
        let data = vec![1u8, 2u8];
        let ret = use_device().unwrap().ext_ecc_verify(&pub_key, &data, &sign);
        println!("ext_ecc_verify result: {:?}", &ret);
        assert!(ret.is_ok());
    }
    #[test]
    fn ecc_verify_test() {
        let pub_key = ECCPublicKeyBlob::default();
        let sign = ECCSignatureBlob::default();
        let data = vec![1u8, 2u8];
        let ret = use_device().unwrap().ecc_verify(&pub_key, &data, &sign);
        println!("ecc_verify result: {:?}", &ret);
        assert!(ret.is_ok());
    }
    #[test]
    fn ecc_gen_session_key_test() {
        let engine = use_stub_engine().unwrap();
        let manager = engine.device_manager().unwrap();
        let device = manager.connect("any");

        let agreement_key =
            ManagedKeyImpl::try_new(raw_handle(MOCK_AGREEMENT_KEY_HANDLE_VALUE), &engine.lib)
                .unwrap();
        let responder_key = ECCPublicKeyBlob::default();
        let responder_tmp_key = ECCPublicKeyBlob::default();
        let responder_id = vec![1u8, 2u8, 3u8];

        let ret = device.unwrap().ecc_gen_session_key(
            &agreement_key,
            &responder_key,
            &responder_tmp_key,
            &responder_id,
        );
        println!("ecc_gen_session_key result: {:?}", &ret);
        assert!(ret.is_ok());
    }
}
