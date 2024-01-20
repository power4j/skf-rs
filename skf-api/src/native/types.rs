//! GM/T 0016-2012 types
//!
//! see [GM/T 0016-2012](https://github.com/guanzhi/GM-Standards/blob/master/GMT%E5%AF%86%E7%A0%81%E8%A1%8C%E6%A0%87/GMT%200017-2012%20%E6%99%BA%E8%83%BD%E5%AF%86%E7%A0%81%E9%92%A5%E5%8C%99%E5%AF%86%E7%A0%81%E5%BA%94%E7%94%A8%E6%8E%A5%E5%8F%A3%E6%95%B0%E6%8D%AE%E6%A0%BC%E5%BC%8F%E8%A7%84%E8%8C%83.PDF)

use std::ffi;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct Void {
    _inner: [u8; 0],
}

pub type INT8 = i8;
pub type INT16 = i16;
pub type INT32 = i32;
pub type SHORT = INT16;
pub type LONG = INT32;
pub type UINT8 = u8;
pub type UINT16 = u16;
pub type UINT32 = u32;
pub type UINT = INT32;
pub type USHORT = UINT16;
pub type ULONG = UINT32;

pub type BOOL = bool;
pub type BYTE = UINT8;
pub type CHAR = UINT8;

pub type WORD = UINT16;

pub type DWORD = UINT32;
pub type FLAGS = UINT32;

pub type LPSTR = *const CHAR;
pub type DEV_HANDLE = *const Void;
pub type H_APPLICATION = ffi::c_void;
pub type H_CONTAINER = ffi::c_void;

pub const TRUE: BOOL = true as BOOL;
pub const FALSE: BOOL = true as BOOL;

pub const DEV_LOCK_FOREVER: ULONG = 0xffffffff;
pub const ADMIN_TYPE: BYTE = 0x0;
pub const USER_TYPE: BYTE = 0x1;

pub const MAX_RSA_MODULUS_LEN: usize = 256;
pub const MAX_RSA_EXPONENT_LEN: usize = 4;

pub const ECC_MAX_X_COORDINATE_BITS_LEN: usize = 512;
pub const ECC_MAX_Y_COORDINATE_BITS_LEN: usize = 512;
pub const ECC_MAX_MODULUS_BITS_LEN: usize = 512;

pub const MAX_IV_LEN: usize = 32;
pub const MAX_FILE_NAME_LEN: usize = 32;
pub const MAX_CONTAINER_NAME_LEN: usize = 128;
pub const MIN_PIN_LEN: usize = 6;

pub const SECURE_NEVER_ACCOUNT: UINT32 = 0x00000000;
pub const SECURE_ADM_ACCOUNT: UINT32 = 0x00000001;
pub const SECURE_USER_ACCOUNT: UINT32 = 0x00000010;
pub const SECURE_EVERYONE_ACCOUNT: UINT32 = 0x000000FF;

/// The structure of `VERSION`
#[derive(Debug, Copy, Clone)]
#[repr(C)]
#[repr(align(1))]
pub struct Version {
    pub major: BYTE,
    pub minor: BYTE,
}

/// The structure of `DEVINFO`
#[derive(Debug, Copy, Clone)]
#[repr(C)]
#[repr(align(1))]
pub struct DeviceInfo {
    pub version: Version,
    pub manufacturer: [CHAR; 64],
    pub issuer: [CHAR; 64],
    pub label: [CHAR; 32],
    pub serial_number: [CHAR; 32],
    pub hw_version: Version,
    pub firmware_version: Version,
    pub alg_sym_cap: ULONG,
    pub alg_asym_cap: ULONG,
    pub alg_hash_cap: ULONG,
    pub dev_auth_alg_id: ULONG,
    pub total_space: ULONG,
    pub free_space: ULONG,
    pub max_ecc_buffer_size: ULONG,
    pub max_buffer_size: ULONG,
    pub reserved: [BYTE; 64],
}

/// The structure of `RSAPUBLICKEYBLOB`
#[derive(Debug, Copy, Clone)]
#[repr(C)]
#[repr(align(1))]
pub struct RSAPublicKeyBlob {
    pub alg_id: ULONG,
    pub bit_leb: ULONG,
    pub version: Version,
    pub modulus: [BYTE; MAX_RSA_MODULUS_LEN],
    pub public_exponent: [BYTE; MAX_RSA_EXPONENT_LEN],
}

/// The structure of `RSAPRIVATEKEYBLOB`
#[derive(Debug, Copy, Clone)]
#[repr(C)]
#[repr(align(1))]
pub struct RSAPrivateKeyBlob {
    pub alg_id: ULONG,
    pub bit_leb: ULONG,
    pub modulus: [BYTE; MAX_RSA_MODULUS_LEN],
    pub public_exponent: [BYTE; MAX_RSA_EXPONENT_LEN],
    pub private_exponent: [BYTE; MAX_RSA_MODULUS_LEN],
    pub prime1: [BYTE; MAX_RSA_MODULUS_LEN / 2],
    pub prime2: [BYTE; MAX_RSA_MODULUS_LEN / 2],
    pub prime1_exponent: [BYTE; MAX_RSA_MODULUS_LEN / 2],
    pub prime2_exponent: [BYTE; MAX_RSA_MODULUS_LEN / 2],
    pub coefficient: [BYTE; MAX_RSA_MODULUS_LEN / 2],
}

/// The structure of `ECCPUBLICKEYBLOB`
#[derive(Debug, Copy, Clone)]
#[repr(C)]
#[repr(align(1))]
pub struct ECCPublicKeyBlob {
    pub bit_leb: ULONG,
    pub x_coordinate: [BYTE; ECC_MAX_X_COORDINATE_BITS_LEN / 8],
    pub y_coordinate: [BYTE; ECC_MAX_Y_COORDINATE_BITS_LEN / 8],
}

/// The structure of `ECCPRIVATEKEYBLOB`
#[derive(Debug, Copy, Clone)]
#[repr(C)]
#[repr(align(1))]
pub struct ECCPrivateKeyBlob {
    pub bit_leb: ULONG,
    pub private_key: [BYTE; ECC_MAX_MODULUS_BITS_LEN / 8],
}

/// The structure of `ECCCIPHERBLOB`
#[derive(Debug, Copy, Clone)]
#[repr(C)]
#[repr(align(1))]
pub struct ECCCipherBlob {
    pub x_coordinate: [BYTE; ECC_MAX_X_COORDINATE_BITS_LEN / 8],
    pub y_coordinate: [BYTE; ECC_MAX_Y_COORDINATE_BITS_LEN / 8],
    pub hash: [BYTE; 32],
    pub cipher_len: ULONG,
    pub cipher: [BYTE; 1],
}

/// The structure of `ECCSIGNATUREBLOB`
#[derive(Debug, Copy, Clone)]
#[repr(C)]
#[repr(align(1))]
pub struct ECCSignatureBlob {
    pub r: [BYTE; ECC_MAX_X_COORDINATE_BITS_LEN / 8],
    pub s: [BYTE; ECC_MAX_Y_COORDINATE_BITS_LEN / 8],
}

/// The structure of `ENVELOPEDKEYBLOB`
#[derive(Debug, Copy, Clone)]
#[repr(C)]
#[repr(align(1))]
pub struct SKFEnvelopedKeyBlob {
    pub version: ULONG,
    pub sym_alg_id: ULONG,
    pub bits: ULONG,
    pub cb_encrypted_pri_key: [BYTE; 64],
    pub pub_key: ECCPublicKeyBlob,
    pub ecc_cipher_blob: ECCCipherBlob,
}

/// The structure of `BLOCKCIPHERPARAM`
#[derive(Debug, Copy, Clone)]
#[repr(C)]
#[repr(align(1))]
pub struct BlockCipherParam {
    pub iv: [BYTE; MAX_IV_LEN],
    pub iv_len: ULONG,
    pub padding_type: ULONG,
    pub feed_bit_len: ULONG,
}

/// The structure of `FILEATTRIBUTE`
#[derive(Debug, Copy, Clone)]
#[repr(C)]
#[repr(align(1))]
pub struct FileAttribute {
    pub file_name: [CHAR; 32],
    pub file_size: ULONG,
    pub read_rights: ULONG,
    pub write_rights: ULONG,
}
