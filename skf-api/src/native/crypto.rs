//! 密码服务接口
//! - SKF_GetRandom
//! - SKF_GenExtRSAKey
//! - SKF_GenRSAKeyPair
//! - SKF_ImportRSAKeyPair
//! - SKF_RSASignData
//! - SKF_RSAVerify
//! - SKF_RSAExportSessionKey
//! - SKF_ExtRSAPubKeyOperation
//! - SKF_ExtRSAPriKeyOperation
//! - SKF_GenECCKeyPair
//! - SKF_ImportECCKeyPair
//! - SKF_ECCSignData
//! - SKF_ECCVerify
//! - SKF_ECCExportSessionKey
//! - SKF_ExtECCEncrypt
//! - SKF_ExtECCDecrypt
//! - SKF_ExtECCSign
//! - SKF_ExtECCVerify
//! - SKF_ExportPublicKey
//! - SKF_ImportSessionKey
//! - SKF_SetSymmKey
//! - SKF_EncryptInit
//! - SKF_Encrypt
//! - SKF_EncryptUpdate
//! - SKF_EncryptFinal
//! - SKF_DecryptInit
//! - SKF_Decrypt
//! - SKF_DecryptUpdate
//! - SKF_DecryptFinal
//! - SKF_DegistInit
//! - SKF_Degist
//! - SKF_DegistUpdate
//! - SKF_DegistFinal
//! - SKF_MACInit
//! - SKF_MAC
//! - SKF_MACUpdate
//! - SKF_MACFinal
//!
//! see [GM/T 0016-2012](https://github.com/guanzhi/GM-Standards/blob/master/GMT%E5%AF%86%E7%A0%81%E8%A1%8C%E6%A0%87/GMT%200017-2012%20%E6%99%BA%E8%83%BD%E5%AF%86%E7%A0%81%E9%92%A5%E5%8C%99%E5%AF%86%E7%A0%81%E5%BA%94%E7%94%A8%E6%8E%A5%E5%8F%A3%E6%95%B0%E6%8D%AE%E6%A0%BC%E5%BC%8F%E8%A7%84%E8%8C%83.PDF)

use crate::native::types::{BlockCipherParam, BYTE, HANDLE, ULONG};

#[allow(non_camel_case_types)]
extern "C" {

    /// 产生指定长度的随机数
    ///
    /// [device_handle] `[IN]`设备句柄
    pub fn SKF_GenRandom(device_handle: HANDLE, data: *mut BYTE, len: ULONG) -> ULONG;

    /// 明文导入会话密钥，返回密钥句柄
    ///
    /// [device_handle] `[IN]`设备句柄
    ///
    /// [key_data] `[IN]`指向会话密钥值的缓冲区
    ///
    /// [alg_id] `[IN]`会话密钥的算法标识
    ///
    /// [key_handle] `[OUT]`返回会话密钥句柄
    pub fn SKF_SetSymmKey(
        device_handle: HANDLE,
        key_data: *const BYTE,
        alg_id: ULONG,
        key_handle: *mut HANDLE,
    ) -> ULONG;

    /// 数据加密初始化。设置数据加密的算法相关参数。
    ///
    /// [key_handle] `[IN]`加密密钥句柄
    ///
    /// [encrypt_param] `[IN]`分组密码算法相关参数：算法标识号、密钥长度、初始向量、初始向量长度、填充方法、加密模式、反馈值的位长度
    pub fn SKF_EncryptInit(key_handle: HANDLE, encrypt_param: BlockCipherParam) -> ULONG;

    /// 单一分组数据的加密操作
    /// 用指定加密密钥对指定数据进行加密，被加密的数据只包含一个分组，加密后的密文保存到指定的缓冲区中。
    ///
    /// [key_handle] `[IN]`加密密钥句柄
    ///
    /// [data] `[IN]`待加密数据
    ///
    /// [data_len] `[IN]`待加密数据长度
    ///
    /// [encrypted_data] `[OUT]`加密后的数据缓冲区指针
    ///
    /// [encrypted_len] `[IN,OUT]`输入，给出的缓冲区大小；输出，返回加密后的数据
    /// ## 注意
    /// - `SKF_Encrypt`只对单个分组数据进行加密，在调用`SKF_Encrypt`之前，必须调用`SKF_EncryptInit`初始化加密操作。
    /// - `SKF_Encrypt`等价于先调用`SKF_EncryptUpdate`再调用`SKF_EncryptFinal`。
    ///
    /// ## 返回值
    /// - 成功: `SAR_OK`
    /// - 失败: `SAR_FAIL`, `SAR_MEMORYERR`, `SAR_UNKNOWNERR`,  `SAR_INVALIDPARAMERR`, `SAR_BUFFER_TOO_SMALL`
    pub fn SKF_Encrypt(
        key_handle: HANDLE,
        data: *const BYTE,
        data_len: ULONG,
        encrypted_data: *mut BYTE,
        encrypted_len: *mut ULONG,
    ) -> ULONG;

    /// 多个分组数据的加密操作。
    /// 用指定加密密钥对指定数据进行加密，被加密的数据包含多个分组，加密后的密文保存到指定的缓冲区中。
    ///
    /// [key_handle] `[IN]`加密密钥句柄
    ///
    /// [data] `[IN]`待加密数据
    ///
    /// [data_len] `[IN]`待加密数据长度
    ///
    /// [encrypted_data] `[OUT]`加密后的数据缓冲区指针
    ///
    /// [encrypted_len] `[OUT]`返回加密后的数据长度
    /// ## 注意
    /// - `SKF_EncryptUpdate`对多个分组数据进行加密，在调用`SKF_EncryptUpdate`之前，必须调用`SKF_EncryptInit`初始化加密操作
    /// - 在调用`SKF_EncryptUpdate`之后，必须调用`SKF_EncryptFinal`结束加密操作
    pub fn SKF_EncryptUpdate(
        key_handle: HANDLE,
        data: *const BYTE,
        data_len: ULONG,
        encrypted_data: *mut BYTE,
        encrypted_len: *mut ULONG,
    ) -> ULONG;

    /// 结束多个分组数据的加密，返回剩余加密结果。
    ///
    /// [key_handle] `[IN]`加密密钥句柄
    ///
    /// [data] `[OUT]`加密结果的缓冲区
    ///
    /// [data_len] `[OUT]`加密结果的长度
    /// ## 注意
    /// - 先调用SKF_EncryptInit初始化加密操作
    /// - 再调用SKF_EncryptUpdate对多个分组数据进行加密
    /// - 最后调用SKF_EncryptFinal结束多个分组数据的加密
    pub fn SKF_EncryptFinal(key_handle: HANDLE, data: *mut BYTE, data_len: *mut ULONG) -> ULONG;

    /// 关闭会话密钥、杂凑、消息认证码句柄
    ///
    /// [key_handle] `[IN]`密钥句柄
    pub fn SKF_CloseHandle(key_handle: HANDLE) -> ULONG;

}
