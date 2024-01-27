//! 应用管理接口
//! - SKF_CreateApplication
//! - SKF_EnumApplication
//! - SKF_DeleteApplication
//! - SKF_OpenApplication
//! - SKF_CloseApplication
//!
//! 文件管理接口
//! - SKF_CreateFile
//! - SKF_DeleteFile
//! - SKF_EnumFiles
//! - SKF_GetFileInfo
//! - SKF_ReadFile
//! - SKF_WriteFile
//!
//! 容器管理接口
//! - SKF_CreateContainer
//! - SKF_DeleteContainer
//! - SKF_OpenContainer
//! - SKF_CloseContainer
//! - SKF_EnumContainer
//!
//! see [GM/T 0016-2012](https://github.com/guanzhi/GM-Standards/blob/master/GMT%E5%AF%86%E7%A0%81%E8%A1%8C%E6%A0%87/GMT%200017-2012%20%E6%99%BA%E8%83%BD%E5%AF%86%E7%A0%81%E9%92%A5%E5%8C%99%E5%AF%86%E7%A0%81%E5%BA%94%E7%94%A8%E6%8E%A5%E5%8F%A3%E6%95%B0%E6%8D%AE%E6%A0%BC%E5%BC%8F%E8%A7%84%E8%8C%83.PDF)

use crate::native::types::{FileAttribute, BOOL, BYTE, CHAR, DWORD, HANDLE, LPSTR, ULONG};

#[allow(non_camel_case_types)]
extern "C" {

    /// 创建一个应用
    ///
    /// [device_handle]		`[IN]`连接设备时返回的设备句柄
    ///
    /// [sz_app_name]		`[IN]`应用名称
    ///
    /// [sz_admin_pin]		`[IN]`管理员PIN
    ///
    /// [admin_pin_retry_count]	`[IN]`管理员PIN最大重试次数
    ///
    /// [sz_user_pin]		`[IN]`用户PIN
    ///
    /// [user_pin_retry_count]	`[IN]`用户PIN最大重试次数
    ///
    /// [create_file_rights]	`[IN]`在该应用下创建文件和容器的权限
    ///
    /// [app_handle]		`[OUT]`应用的句柄
    pub fn SKF_CreateApplication(
        device_handle: HANDLE,
        sz_app_name: LPSTR,
        sz_admin_pin: LPSTR,
        admin_pin_retry_count: DWORD,
        sz_user_pin: LPSTR,
        user_pin_retry_count: DWORD,
        create_file_rights: DWORD,
        app_handle: *mut HANDLE,
    ) -> ULONG;

    /// 枚举设备中所存在的所有应用
    ///
    /// [device_handle]		`[IN]`连接设备时返回的设备句柄
    ///
    /// [sz_app_name_list]	`[OUT]`返回应用名称列表, 如果该参数为空，将由`size`返回所需要的内存空间大小。每个应用的名称以单个'\0'结束，以双'\0'表示列表的结束。
    ///
    /// [size]				`[IN,OUT]`输入参数，输入应用名称的缓冲区长度，输出参数，返回`sz_app_name_list`所占用的的空间大小
    pub fn SKF_EnumApplication(
        device_handle: HANDLE,
        sz_app_name_list: LPSTR,
        size: *mut ULONG,
    ) -> ULONG;

    /// 打开指定的应用
    ///
    /// [device_handle]		`[IN]`连接设备时返回的设备句柄
    ///
    /// [sz_app_name]		`[IN]`应用名称
    ///
    /// [app_handle]		`[OUT]`应用的句柄
    pub fn SKF_OpenApplication(
        device_handle: HANDLE,
        sz_app_name: LPSTR,
        app_handle: *mut HANDLE,
    ) -> ULONG;

    /// 删除指定的应用
    ///
    /// [device_handle]		`[IN]`连接设备时返回的设备句柄
    ///
    /// [sz_app_name]		`[IN]`应用名称
    pub fn SKF_DeleteApplication(device_handle: HANDLE, sz_app_name: LPSTR) -> ULONG;

    /// 关闭应用并释放应用句柄
    ///
    /// [app_handle]		`[IN]`应用的句柄
    pub fn SKF_CloseApplication(app_handle: HANDLE) -> ULONG;

    /// 创建一个文件。创建文件时要指定文件的名称，大小，以及文件的读写权限
    ///
    /// [app_handle]		`[IN]`应用句柄
    ///
    /// [sz_file_name]		`[IN]`文件名称，长度不得大于32个字节
    ///
    /// [file_size]			`[IN]`文件大小
    ///
    /// [read_rights]		`[IN]`文件读权限
    ///
    /// [write_rights]		`[IN]`文件写权限
    pub fn SKF_CreateFile(
        app_handle: HANDLE,
        sz_file_name: LPSTR,
        file_size: ULONG,
        read_rights: ULONG,
        write_rights: ULONG,
    ) -> ULONG;

    /// 删除指定文件，文件删除后，文件中写入的所有信息将丢失。文件在设备中的占用的空间将被释放。
    ///
    /// [app_handle]		`[IN]`要删除文件所在的应用句柄
    ///
    /// [sz_file_name]		`[IN]`要删除文件的名称
    pub fn SKF_DeleteFile(app_handle: HANDLE, sz_file_name: LPSTR) -> ULONG;

    /// 枚举一个应用下存在的所有文件
    ///
    /// [app_handle]		`[IN]`应用的句柄
    ///
    /// [sz_file_list]		`[OUT]`返回文件名称列表，该参数为空，由`size`返回文件信息所需要的空间大小。每个文件名称以单个`'\0'`结束，以双`'\0'`表示列表的结束。
    pub fn SKF_EnumFiles(app_handle: HANDLE, sz_file_list: *mut CHAR, size: *mut ULONG) -> ULONG;

    /// 获取应用文件的属性信息，例如文件的大小、权限等
    ///
    /// [app_handle]		`[IN]`文件所在应用的句柄
    ///
    /// [sz_file_name]		`[IN]`文件名称
    ///
    /// [file_info]			`[OUT]`文件信息，指向文件属性结构的指针
    pub fn SKF_GetFileInfo(
        app_handle: HANDLE,
        sz_file_name: LPSTR,
        file_info: *mut FileAttribute,
    ) -> ULONG;

    /// 读取文件内容
    ///
    /// [app_handle]		`[IN]`文件所在的应用句柄
    ///
    /// [sz_file_name]		`[IN]`文件名
    ///
    /// [offset]			`[IN]`文件读取偏移位置
    ///
    /// [size]				`[IN]`要读取的长度
    ///
    /// [out_data]			`[OUT]`返回数据的缓冲区
    ///
    /// [out_len]			`[OUT]`输入表示给出的缓冲区大小，输出表示实际读取返回的数据大小
    pub fn SKF_ReadFile(
        app_handle: HANDLE,
        sz_file_name: LPSTR,
        offset: ULONG,
        size: ULONG,
        out_data: *mut BYTE,
        out_len: *mut ULONG,
    ) -> ULONG;

    /// 写数据到文件中
    ///
    /// [app_handle]		`[IN]`文件所在的应用句柄
    ///
    /// [sz_file_name]		`[IN]`文件名
    ///
    /// [offset]			`[IN]`写入文件的偏移量
    ///
    /// [data]				`[IN]`写入数据缓冲区
    ///
    /// [size]				`[IN]`写入数据的大小
    pub fn SKF_WriteFile(
        app_handle: HANDLE,
        sz_file_name: LPSTR,
        offset: ULONG,
        data: *const BYTE,
        size: ULONG,
    ) -> ULONG;

    /// 在应用下建立指定名称的容器并返回容器句柄
    ///
    /// [app_handle]		`[IN]`应用句柄
    ///
    /// [sz_container_name]	`[IN]`ASCII字符串，表示所建立容器的名称，容器名称的最大长度不能超过64字节
    ///
    /// [container_handle]	`[OUT]`返回所建立容器的容器句柄
    pub fn SKF_CreateContainer(
        app_handle: HANDLE,
        sz_container_name: LPSTR,
        container_handle: *mut HANDLE,
    ) -> ULONG;

    /// 在应用下删除指定名称的容器并释放容器相关的资源
    ///
    /// [app_handle]		`[IN]`应用句柄
    ///
    /// [sz_container_name]	`[IN]`指向删除容器的名称
    pub fn SKF_DeleteContainer(app_handle: HANDLE, sz_container_name: LPSTR) -> ULONG;

    /// 获取容器句柄
    ///
    /// [app_handle]		`[IN]`应用句柄
    ///
    /// [sz_container_name]	`[IN]`容器名称
    ///
    /// [container_handle]	`[OUT]`返回所打开容器的句柄
    pub fn SKF_OpenContainer(
        app_handle: HANDLE,
        sz_container_name: LPSTR,
        container_handle: *mut HANDLE,
    ) -> ULONG;

    /// 关闭容器句柄，并释放容器句柄相关资源
    ///
    /// [container_handle]		`[IN]`容器句柄
    ///
    pub fn SKF_CloseContainer(container_handle: HANDLE) -> ULONG;

    /// 枚举应用下的所有容器并返回容器名称列表
    ///
    /// [app_handle]		`[IN]`应用句柄
    ///
    /// [list] 			`[OUT]`指向容器名称列表缓冲区
    /// 如果此参数为`NULL`时，`size`表示返回数据所需要缓冲区的长度，如果此参数不为`NULL`时，返回容器名称列表，每个容器名以单个`'\0'`为结束，列表以双`'\0'`结束
    ///
    /// [size]				`[IN,OUT]`输入参数，输入容器名称列表的缓冲区长度，输出参数，返回容器名称列表所占用的的空间大小
    pub fn SKF_EnumContainer(app_handle: HANDLE, list: *mut CHAR, size: *mut ULONG) -> ULONG;

    /// 获取容器的类型
    ///
    /// [container_handle]		`[IN]`容器句柄
    ///
    /// [container_type]		`[OUT]`获得的容器类型。值为`0`表示未定、尚未分配类型或者为空容器，`1`表示为`RSA`容器，`2`表示为`ECC`容器。
    pub fn SKF_GetContainerType(container_handle: HANDLE, container_type: *mut ULONG) -> ULONG;

    /// 向容器内导入数字证书。
    ///
    /// [container_handle] `[IN]`容器句柄。
    ///
    /// [sign_flag] `[IN]` `TRUE`表示签名证书，`FALSE`表示加密证书。
    ///
    /// [cert] `[IN]`指向证书内容缓冲区。
    ///
    /// [cert_len] `[IN]`证书长度。
    pub fn SKF_ImportCertificate(
        container_handle: HANDLE,
        sign_flag: BOOL,
        cert: *const BYTE,
        cert_len: ULONG,
    ) -> ULONG;

    /// 从容器内导出数字证书。
    ///
    /// [container_handle] `[IN]`容器句柄。
    ///
    /// [sign_flag] `[IN]` `TRUE`表示签名证书，`FALSE`表示加密证书。
    ///
    /// [cert] `[OUT]`指向证书内容缓冲区，如果此参数为 `NULL`时，`cert_len`表示返回数据所需要缓冲区的长度。如果此参数不为 `NULL`时，返回数字证书内容
    ///
    /// [cert_len] `[IN,OUT]`输入时表示`cert`缓冲区的长度，输出时表示证书内容的长度。
    pub fn SKF_ExportCertificate(
        container_handle: HANDLE,
        sign_flag: BOOL,
        cert: *mut BYTE,
        cert_len: *mut ULONG,
    ) -> ULONG;
}
