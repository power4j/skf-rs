//! 访问控制接口
//! - SKF_ChangeDevAuthKey
//! - SKF_DevAuth
//! - SKF_ChangePIN
//! - SKF_GetPINInfo
//! - SKF_VerifyPIN
//! - SKF_UnblockPIN
//! - SKF_ClearSecureState
//!
//! see [GM/T 0016-2012](https://github.com/guanzhi/GM-Standards/blob/master/GMT%E5%AF%86%E7%A0%81%E8%A1%8C%E6%A0%87/GMT%200017-2012%20%E6%99%BA%E8%83%BD%E5%AF%86%E7%A0%81%E9%92%A5%E5%8C%99%E5%AF%86%E7%A0%81%E5%BA%94%E7%94%A8%E6%8E%A5%E5%8F%A3%E6%95%B0%E6%8D%AE%E6%A0%BC%E5%BC%8F%E8%A7%84%E8%8C%83.PDF)
//!
//! ## 权限分类
//! 权限分为设备权限，用户权限和管理员权限。
//! - 设备权限：通过设备认证后获得设备权限。
//! - 用户权限：用户PIN码验证通过后，获得用户权限，用户权限只作用于其所在的应用。
//! - 管理员权限：管理员PIN码验证通过后，获得管理员权限，管理员权限只作用于其所在的应用。
//!
//! ## 设备认证
//!  必须通过设备认证后才能在设备内创建和删除应用。设备认证使用分组密码算法和设备认证密钥进行。认证的流程如下：
//!  1. 被认证方调用SKF_GetRandom 函数从设备获取8字节随机数 RND，并用`0x00`将其填充至密码算法的分块长度，组成数据块 `D0`
//!  2. 被认证方对`D0`加密，得到加密结果`D1`，并调用`SKF_DevAuth`，将`D1`发送至设备；
//!  3. 设备收到`D1`后，验证`D1`是否正确。正确则通过设备认证，否则设备认证失败。

use crate::native::types::{BOOL, BYTE, HANDLE, LPSTR, ULONG};

#[allow(non_camel_case_types)]
extern "C" {

    /// 更改设备认证密钥
    ///
    /// [device_handle]		`[IN]`连接时返回的设备句柄
    ///
    /// [key_value]		`[IN]`密钥值
    ///
    /// [key_len]		`[IN]`密钥长度
    /// ## 权限要求
    /// 设备认证成功后才能使用。
    pub fn SKF_ChangeDevAuthKey(
        device_handle: HANDLE,
        key_value: *const BYTE,
        key_len: ULONG,
    ) -> ULONG;

    /// 设备认证
    ///
    /// [device_handle]		`[IN]`连接时返回的设备句柄
    ///
    /// [auth_data]		`[IN]`认证数据
    ///
    /// [len]		`[IN]`认证数据的长度
    pub fn SKF_DevAuth(device_handle: HANDLE, auth_data: *const BYTE, len: ULONG) -> ULONG;

    /// 修改PIN.可以修改Admin和User的PIN，如果原PIN错误，返回剩余重试次数，当剩余次数为0时，表示PIN已经被锁死
    ///
    /// [app_handle]		`[IN]`应用句柄
    ///
    /// [pin_type]		`[IN]`PIN类型，ADMIN_TYPE=0,USER_TYPE=1
    ///
    /// [sz_old_pin]		`[IN]`原PIN值
    ///
    /// [sz_new_pin]		`[IN]`新PIN值
    ///
    /// [retry_count]	`[OUT]`出错后重试次数
    pub fn SKF_ChangePIN(
        app_handle: HANDLE,
        pin_type: ULONG,
        sz_old_pin: LPSTR,
        sz_new_pin: LPSTR,
        retry_count: *mut ULONG,
    ) -> ULONG;

    /// 获取PIN码信息，包括最大重试次数、当前剩余重试次数，以及当前PIN码是否为出厂默认PIN码
    ///
    /// [app_handle]		`[IN]`应用句柄
    ///
    /// [pin_type]		`[IN]`PIN类型
    ///
    /// [max_retry_count]	`[OUT]`最大重试次数
    ///
    /// [remain_retry_count]	`[OUT]`当前剩余重试次数，当为0时表示已锁死
    ///
    /// [default_pin]		`[OUT]`是否为出厂默认PIN码
    pub fn SKF_GetPINInfo(
        app_handle: HANDLE,
        pin_type: ULONG,
        max_retry_count: *mut ULONG,
        remain_retry_count: *mut ULONG,
        default_pin: *mut BOOL,
    ) -> ULONG;

    /// 校验PIN码。校验成功后，会获得相应的权限，如果PIN码错误，会返回PIN码的重试次数，当重试次数为0时表示PIN码已经锁死
    ///
    /// [app_handle]		`[IN]`应用句柄
    ///
    /// [pin_type]		`[IN]`PIN类型，ADMIN_TYPE=0,USER_TYPE=1
    ///
    /// [sz_pin]		`[IN]`PIN值
    ///
    /// [retry_count]	`[OUT]`出错后返回的重试次数
    pub fn SKF_VerifyPIN(
        app_handle: HANDLE,
        pin_type: ULONG,
        sz_pin: LPSTR,
        retry_count: *mut ULONG,
    ) -> ULONG;

    /// 解锁用户PIN码.当用户的PIN码锁死后，通过调用该函数来解锁用户PIN码。解锁后，用户PIN码被设置成新值，用户PIN码的重试次数也恢复到原值。
    ///
    /// 验证完管理员 PIN才能够解锁用户  PIN 码，如果输入的 管理员 PIN 不正确或者已经锁死，会调用失败，并返回 管理员 PIN 的重试次数。
    ///
    /// [app_handle]		`[IN]`应用句柄
    ///
    /// [sz_admin_pin]	`[IN]`管理员PIN码
    ///
    /// [sz_new_user_pin]	`[IN]`新的用户PIN码
    ///
    /// [retry_count]	`[OUT]`管理员PIN码错误时，返回剩余重试次数
    ///
    pub fn SKF_UnblockPIN(
        app_handle: HANDLE,
        sz_admin_pin: LPSTR,
        sz_new_user_pin: LPSTR,
        retry_count: *mut ULONG,
    ) -> ULONG;

    /// 清除应用当前的安全状态
    ///
    /// [app_handle]	`[IN]`应用句柄
    pub fn SKF_ClearSecureState(handle: HANDLE) -> ULONG;
}
