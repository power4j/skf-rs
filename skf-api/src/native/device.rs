//! 设备管理接口
//! - SKF_WaitForDevEvent
//! - SKF_CancelWaitForDevEvent
//! - SKF_EnumDev
//! - SKF_ConnectDev
//! - SKF_DisconnectDev
//! - SKF_GetDevState
//! - SKF_SetLabel
//! - SKF_GetDevInfo
//! - SKF_LockDev
//! - SKF_UnlockDev
//! - SKF_Transmit
//!
//! see [GM/T 0016-2012](https://github.com/guanzhi/GM-Standards/blob/master/GMT%E5%AF%86%E7%A0%81%E8%A1%8C%E6%A0%87/GMT%200017-2012%20%E6%99%BA%E8%83%BD%E5%AF%86%E7%A0%81%E9%92%A5%E5%8C%99%E5%AF%86%E7%A0%81%E5%BA%94%E7%94%A8%E6%8E%A5%E5%8F%A3%E6%95%B0%E6%8D%AE%E6%A0%BC%E5%BC%8F%E8%A7%84%E8%8C%83.PDF)

use crate::native::types::{DeviceInfo, BOOL, BYTE, HANDLE, LPSTR, ULONG};

#[allow(non_camel_case_types)]
extern "C" {

    /// 等待设备的插拔事件
    ///
    /// 备注: 该函数是阻塞调用
    ///
    /// [sz_dev_name]		`[OUT]`返回发生事件的设备名称
    ///
    /// [dev_name_len]	`[IN,OUT]`输入/输出参数，当输入时表示缓冲区长度，输出时表示设备名称的有效长度,长度包含字符串结束符
    ///
    /// [event]		`[OUT]`事件类型。1表示插入，2表示拔出
    pub fn SKF_WaitForDevEvent(
        sz_dev_name: LPSTR,
        dev_name_len: *mut ULONG,
        event: *mut ULONG,
    ) -> ULONG;

    ///	取消等待设备插拔事件
    pub fn SKF_CancelWaitForDevEvent() -> ULONG;

    ///	获得当前系统中的设备列表
    ///
    ///	[b_present]		`[IN]`为TRUE表示取当前设备状态为存在的设备列表。为FALSE表示取当前驱动支持的设备列表
    ///
    ///	[sz_name_list]	`[OUT]`设备名称列表。如果该参数为NULL，将由 `size` 返回所需要的内存空间大小。每个设备的名称以单个`'\0'`结束，以双`'\0'`表示列表的结束
    ///
    ///	[size]			`[IN,OUT]`输入参数，输入设备名称列表的缓冲区长度，输出参数，返回szNameList所需要的空间大小
    ///
    pub fn SKF_EnumDev(b_present: BOOL, sz_name_list: LPSTR, size: *mut ULONG) -> ULONG;

    /// 通过设备名称连接设备，返回设备的句柄
    ///
    /// [sz_name]		`[IN]`设备名称
    ///
    /// [handle]		`[OUT]`返回设备操作句柄
    pub fn SKF_ConnectDev(sz_name: LPSTR, handle: *mut HANDLE) -> ULONG;

    /// 断开一个已经连接的设备，并释放句柄。
    ///
    /// [handle]		`[IN]`连接设备时返回的设备句柄
    pub fn SKF_DisConnectDev(handle: HANDLE) -> ULONG;

    /// 获取设备是否存在的状态
    ///
    /// [sz_dev_name]	`[IN]`连接名称
    ///
    /// [dev_state]	`[OUT]`返回设备状态
    pub fn SKF_GetDevState(sz_dev_name: LPSTR, dev_state: *mut ULONG) -> ULONG;

    /// 设置设备标签
    ///
    /// [handle]		`[IN]`连接设备时返回的设备句柄
    ///
    /// [sz_label]		`[OUT]`设备标签字符串。该字符串应小于32字节
    pub fn SKF_SetLabel(handle: HANDLE, sz_label: LPSTR) -> ULONG;

    /// 获取设备的一些特征信息，包括设备标签、厂商信息、支持的算法等
    ///
    /// [handle]		`[IN]`连接设备时返回的设备句柄
    ///
    /// [dev_info]	[OUT]返回设备信息
    pub fn SKF_GetDevInfo(handle: HANDLE, dev_info: *mut DeviceInfo) -> ULONG;

    /// 获得设备的独占使用权
    ///
    /// [handle]		`[IN]`连接设备时返回的设备句柄
    ///
    /// [timeout]	`[IN]`超时时间，单位为毫秒。如果为`0xFFFFFFFF`表示无限等待
    pub fn SKF_LockDev(handle: HANDLE, timeout: ULONG) -> ULONG;

    /// 释放对设备的独占使用权
    ///
    /// [handle]		`[IN]`连接设备时返回的设备句柄
    pub fn SKF_UnlockDev(handle: HANDLE) -> ULONG;

    /// 设备命令传输
    ///
    /// [handle]		`[IN]`连接设备时返回的设备句柄
    ///
    /// [command]		`[IN]`设备命令
    ///
    /// [command_len]		`[IN]`命令长度
    ///
    /// [data]		`[OUT]`返回结果数据
    ///
    /// [data_len]		`[IN,OUT]`输入时表示结果缓冲区长度，输出时表示结果缓冲区长度实际长度
    pub fn SKF_Transmit(
        handle: HANDLE,
        command: *const BYTE,
        command_len: ULONG,
        data: *mut BYTE,
        data_len: *mut ULONG,
    ) -> ULONG;
}
