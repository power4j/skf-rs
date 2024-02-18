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

use crate::native::types::{
    BlockCipherParam, ECCCipherBlob, ECCPrivateKeyBlob, ECCPublicKeyBlob, ECCSignatureBlob,
    EnvelopedKeyBlob, BOOL, BYTE, HANDLE, ULONG,
};

#[allow(non_camel_case_types)]
extern "C" {

    /// 产生指定长度的随机数
    ///
    /// [device_handle] `[IN]`设备句柄
    pub fn SKF_GenRandom(device_handle: HANDLE, data: *mut BYTE, len: ULONG) -> ULONG;

    /// 关闭会话密钥、杂凑、消息认证码句柄
    ///
    /// [key_handle] `[IN]`密钥句柄
    pub fn SKF_CloseHandle(key_handle: HANDLE) -> ULONG;

    /// 明文导入会话密钥，返回密钥句柄
    ///
    /// **本函数仅用于测试和调试，不建议用于实际的密码服务。**
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

    /// 初始化解密操作
    ///
    /// [key_handle] `[IN]`加密密钥句柄
    ///
    /// [decrypt_param] `[IN]`分组密码算法相关参数：算法标识号、密钥长度、初始向量、初始向量长度、填充方法、加密模式、反馈值的位长度
    pub fn SKF_DecryptInit(key_handle: HANDLE, decrypt_param: BlockCipherParam) -> ULONG;

    /// 单个分组数据的解密操作
    ///
    /// 用指定解密密钥对指定数据进行解密，被解密的数据只包含一个分组，解密后的明文保存到指定的缓冲区中。
    ///
    /// `SKF_Decrypt`只对单个分组数据进行解密，在调用`SKF_Decrypt`之前，必须调用`SKF_DecryptInit`初始化解密操作
    ///
    /// `SKF_Decypt`等价于先调用`SKF_DecryptUpdate`再调用`SKF_DecryptFinal`
    ///
    /// [key_handle] `[IN]`加密密钥句柄
    ///
    /// [encrypted_data] `[IN]`待解密数据
    ///
    /// [encrypted_len] `[IN]`待解密数据长度
    ///
    /// [data] `[OUT]` 指向解密后的数据缓冲区指针，当为NULL时可获得解密后的数据长度
    ///
    /// [data_len] `[IN，OUT]`返回解密后的数据长度
    pub fn SKF_Decrypt(
        key_handle: HANDLE,
        encrypted_data: *const BYTE,
        encrypted_len: ULONG,
        data: *mut BYTE,
        data_len: *mut ULONG,
    ) -> ULONG;

    /// 多个分组数据的解密操作。
    /// 用指定解密密钥对指定数据进行解密，被解密的数据包含多个分组，解密后的明文保存到指定的缓冲区中。
    ///
    /// `SKF_DecryptUpdate`对多个分组数据进行解密，在调用SKF_DecryptUpdate之前，必须调用SKF_DecryptInit初始化解密操作。
    ///
    /// 在调用`SKF_DecryptUpdate`之后，必须调用SKF_DecryptFinal结束解密操作。
    ///
    /// [key_handle] `[IN]`加密密钥句柄
    ///
    /// [encrypted_data] `[IN]`待解密数据
    ///
    /// [encrypted_len] `[IN]`待解密数据长度
    ///
    /// [data] `[OUT]`指向解密后的数据缓冲区指针
    ///
    /// [data_len] `[IN，OUT]`返回解密后的数据长度
    pub fn SKF_DecryptUpdate(
        key_handle: HANDLE,
        encrypted_data: *const BYTE,
        encrypted_len: ULONG,
        data: *mut BYTE,
        data_len: *mut ULONG,
    ) -> ULONG;

    /// 结束多个分组数据的解密
    ///
    /// [key_handle] `[IN]`加密密钥句柄
    ///
    /// [decrypted_data] `[OUT]`解密结果的缓冲区,如果此参数为NULL时，由`decrypted_data_len`返回解密结果的长度
    ///
    /// [decrypted_data_len] `[IN，OUT]`调用时表示`decrypted_data`缓冲区的长度，返回解密结果的长度
    pub fn SKF_DecryptFinal(
        key_handle: HANDLE,
        decrypted_data: *mut BYTE,
        decrypted_data_len: *mut ULONG,
    ) -> ULONG;

    /// 生成ECC签名密钥对
    ///
    /// [ct_handle] `[IN]`容器句柄
    ///
    /// [alg_id] `[IN]`算法标识，只支持`SGD_SM2_1`算法。
    ///
    /// [key_blob] `[OUT]`返回ECC公钥数据结构
    ///
    /// ## 权限要求
    /// 需要用户权限
    pub fn SKF_GenECCKeyPair(
        ct_handle: HANDLE,
        alg_id: ULONG,
        key_blob: *mut ECCPublicKeyBlob,
    ) -> ULONG;

    /// 导入ECC公私钥对
    ///
    /// [ct_handle] `[IN]`容器句柄
    ///
    /// [key_blob] `[IN]`ECC公私钥数据结构
    ///
    /// ## 权限要求
    /// 需要用户权限
    pub fn SKF_ImportECCKeyPair(ct_handle: HANDLE, key_blob: *const EnvelopedKeyBlob) -> ULONG;

    /// ECC数字签名，采用 ECC 算法和指定私钥对指定数据进行数字签名，签名后的结果存放到signature中。
    ///
    /// [ct_handle] `[IN]`容器句柄
    ///
    /// [data] `[IN]`待签名的数据,当使用 SM2算法时，该输入数据为待签数据经过`SM2`签名预处理的结果，预处理过程遵循`GM/T 0009`。
    ///
    /// [data_len] `[IN]`待签名数据长度，必须小于密钥模长。
    ///
    /// [signature] `[OUT]`签名值
    /// ## 权限要求
    /// 需要用户权限
    pub fn SKF_ECCSignData(
        ct_handle: HANDLE,
        data: *const BYTE,
        data_len: ULONG,
        signature: *mut ECCSignatureBlob,
    ) -> ULONG;

    /// 用ECC公钥对数据进行验签
    ///
    /// [device_handle] `[IN]`设备句柄
    ///
    /// [key_blob] `[IN]`ECC公钥数据结构
    ///
    /// [data] `[IN]`待签数据的杂凑值。当使用 SM2算法时，该输入数据为待签数据经过`SM2`签名预处理的结果，预处理过程遵循`GM/T 0009`
    ///
    /// [data_len] `[IN]`数据长度
    ///
    /// [signature] `[IN]`待验证的签名值
    pub fn SKF_ECCVerify(
        device_handle: HANDLE,
        key_blob: *const ECCPublicKeyBlob,
        data: *const BYTE,
        data_len: ULONG,
        signature: *const ECCSignatureBlob,
    ) -> ULONG;

    /// 生成会话密钥并用外部公钥加密输出
    ///
    /// [ct_handle] `[IN]`容器句柄
    ///
    /// [alg_id] `[IN]`会话密钥的算法标识
    ///
    /// [key_blob] `[IN]`外部输入的公钥结构
    ///
    /// [cipher_blob] `[OUT]`会话密钥密文
    ///
    /// [session_key] `[OUT]`会话密钥句柄
    pub fn SKF_ECCExportSessionKey(
        ct_handle: HANDLE,
        alg_id: ULONG,
        key_blob: *const ECCPublicKeyBlob,
        cipher_blob: *mut ECCCipherBlob,
        session_key: *mut HANDLE,
    ) -> ULONG;

    /// 使用外部传入的ECC公钥对输入数据做加密运算并输出结果
    ///
    /// [device_handle] `[IN]`设备句柄
    ///
    /// [key_blob] `[IN]`ECC公钥数据结构
    ///
    /// [data] `[IN]`待加密的明文数据
    ///
    /// [data_len] `[IN]`待加密明文数据的长度
    ///
    /// [cipher_blob] `[OUT]`密文数据
    pub fn SKF_ExtECCEncrypt(
        device_handle: HANDLE,
        key_blob: *const ECCPublicKeyBlob,
        data: *const BYTE,
        data_len: ULONG,
        cipher_blob: *mut ECCCipherBlob,
    ) -> ULONG;

    /// 使用外部传入的ECC私钥对输入数据做解密运算并输出结果
    ///
    /// [device_handle] `[IN]`设备句柄
    ///
    /// [key_blob] `[IN]`ECC私钥数据结构
    ///
    /// [cipher_blob] `[IN]`待解密的密文数据
    ///
    /// [data] `[OUT]`返回明文数据，如果该参数为NULL，则由data_len返回明文数据的实际长度
    ///
    /// [data_len] `[IN,OUT]`调用前表示data缓冲区的长度，返回明文数据的实际长度
    pub fn SKF_ExtECCDecrypt(
        device_handle: HANDLE,
        key_blob: *const ECCPrivateKeyBlob,
        cipher_blob: *const ECCCipherBlob,
        data: *mut BYTE,
        data_len: *mut ULONG,
    ) -> ULONG;

    /// 使用外部传入的ECC私钥对输入数据做签名运算并输出结果。
    ///
    /// **本函数仅用于测试和调试，不建议用于实际的密码服务。**
    ///
    /// [device_handle] `[IN]`设备句柄
    ///
    /// [key_blob] `[IN]`ECC私钥数据结构
    ///
    /// [data] `[IN]`待签数据的杂凑值。当使用 SM2算法时，该输入数据为待签数据经过`SM2`签名预处理的结果，预处理过程遵循`GM/T 0009`
    ///
    /// [data_len] `[IN]`待签名数据的长度
    ///
    /// [signature] `[OUT]`签名值
    pub fn SKF_ExtECCSign(
        device_handle: HANDLE,
        key_blob: *const ECCPrivateKeyBlob,
        data: *const BYTE,
        data_len: ULONG,
        signature: *mut ECCSignatureBlob,
    ) -> ULONG;

    /// 外部使用传入的ECC公钥做签名验证
    ///
    /// **本函数仅用于测试和调试，不建议用于实际的密码服务。**
    ///
    /// [device_handle] `[IN]`设备句柄
    ///
    /// [key_blob] `[IN]`ECC公钥数据结构
    ///
    /// [data] 待`[IN]`签数据的杂凑值。当使用 SM2算法时，该输入数据为待签数据经过`SM2`签名预处理的结果，预处理过程遵循`GM/T 0009`
    ///
    /// [data_len] `[IN]`待验证数据的长度
    ///
    /// [signature] `[IN]`签名值
    pub fn SKF_ExtECCVerify(
        device_handle: HANDLE,
        key_blob: *const ECCPublicKeyBlob,
        data: *const BYTE,
        data_len: ULONG,
        signature: *const ECCSignatureBlob,
    ) -> ULONG;

    /// 使用ECC密钥协商算法，为计算会话密钥而产生协商参数，返回临时ECC密钥对的公钥及协商句柄
    ///
    /// [ct_handle] `[IN]`容器句柄
    ///
    /// [alg_id] `[IN]`会话密钥算法标识
    ///
    /// [key_blob] `[IN]`发起方临时ECC公钥
    ///
    /// [id_data] `[IN]`发起方的ID
    ///
    /// [id_len] `[IN]`发起方ID的长度，不大于32
    ///
    /// [key_handle] `[OUT]`返回的密钥协商句柄
    pub fn SKF_GenerateAgreementDataWithECC(
        ct_handle: HANDLE,
        alg_id: ULONG,
        key_blob: *const ECCPublicKeyBlob,
        id_data: *const BYTE,
        id_len: ULONG,
        key_handle: *mut HANDLE,
    ) -> ULONG;

    /// 使用ECC密钥协商算法，产生协商参数并计算会话密钥，输出临时ECC密钥对公钥，并返回产生的密钥句柄
    ///
    /// [ct_handle] `[IN]`容器句柄
    ///
    /// [alg_id] `[IN]`会话密钥算法标识
    ///
    /// [sponsor_key] `[IN]`发起方的ECC公钥
    ///
    /// [sponsor_tmp_key] `[OUT]`发起方的临时ECC公钥
    ///
    /// [key_blob] `[IN]`响应方的临时ECC公钥
    ///
    /// [id] `[IN]`响应方的ID
    ///
    /// [id_len] `[IN]`响应方ID的长度，不大于32
    ///
    /// [sponsor_id] `[IN]`发起方的ID
    ///
    /// [sponsor_id_len] `[OUT]`发起方ID的长度，不大于32
    pub fn SKF_GenerateAgreementDataAndKeyWithECC(
        ct_handle: HANDLE,
        alg_id: ULONG,
        sponsor_key: *const ECCPublicKeyBlob,
        sponsor_tmp_key: *const ECCPublicKeyBlob,
        tmp_key: *mut ECCPublicKeyBlob,
        id: *const BYTE,
        id_len: ULONG,
        sponsor_id: *const BYTE,
        sponsor_id_len: ULONG,
        key_handle: *mut HANDLE,
    ) -> ULONG;

    /// 使用ECC密钥协商算法，使用自身协商句柄和响应方的协商参数计算会话密钥，同时返回会话密钥句柄
    ///
    /// [agreement_key] `[IN]`密钥协商句柄
    ///
    /// [key_blob] `[IN]`外部输入的响应方ECC公钥
    ///
    /// [tmp_key] `[IN]`外部输入的响应方临时ECC公钥
    ///
    /// [id] `[IN]`响应方的ID
    ///
    /// [id_len] `[IN]`响应方ID的长度，不大于32
    ///
    /// [key_handle] `[OUT]`返回的密钥句柄
    pub fn SKF_GenerateKeyWithECC(
        agreement_key: HANDLE,
        key_blob: *const ECCPublicKeyBlob,
        tmp_key_blob: *const ECCPublicKeyBlob,
        id: *const BYTE,
        id_len: ULONG,
        key_handle: *mut HANDLE,
    ) -> ULONG;

    /// 导出容器中的签名公钥或者加密公钥
    ///
    /// [ct_handle] `[IN]`容器句柄
    ///
    /// [sign_flag] `[IN]`TRUE表示导出签名公钥，FALSE表示导出加密公钥
    ///
    /// [data] `[OUT]`指向导出公钥结构的缓冲区,指向 RSA 公钥结构(`RSAPublicKeyBlob`)或者 ECC公钥结构(`ECCPublicKeyBlob`)，如果此参数为`NULL`时，由data_len返回长度。
    ///
    /// [data_len] `[IN,OUT]`输入时表示导出公钥缓冲区的长度，输出时表示导出公钥结构的大小
    pub fn SKF_ExportPublicKey(
        ct_handle: HANDLE,
        sign_flag: BOOL,
        data: *mut BYTE,
        data_len: *mut ULONG,
    ) -> ULONG;

    /// 导入会话密钥
    ///
    /// [ct_handle] `[IN]`容器句柄
    ///
    /// [alg_id] `[IN]`会话密钥的算法标识
    ///
    /// [data] `[IN]`要导入的会话密钥密文。当容器为 ECC 类型时，此参数为ECCCipherBlob密文数据，当容器为RSA类型时，此参数为RSA公钥加密后的数据
    ///
    /// [data_len] `[IN]`会话密钥密文长度
    ///
    /// [key_handle] `[OUT]`返回会话密钥句柄
    /// ## 权限要求
    /// 需要用户权限
    pub fn SKF_ImportSessionKey(
        ct_handle: HANDLE,
        alg_id: ULONG,
        data: *const BYTE,
        data_len: ULONG,
        key_handle: *mut HANDLE,
    ) -> ULONG;
}
