/// 成功
pub const SAR_OK: u32 = 0x00000000;
/// 失败
pub const SAR_FAIL: u32 = 0x0A000001;
/// 异常错误
pub const SAR_UNKNOWNERR: u32 = 0x0A000002;
/// 不支持的服务
pub const SAR_NOTSUPPORTYETERR: u32 = 0x0A000003;
/// 文件操作错误
pub const SAR_FILEERR: u32 = 0x0A000004;
/// 无效的句柄
pub const SAR_INVALIDHANDLEERR: u32 = 0x0A000005;
/// 无效的参数
pub const SAR_INVALIDPARAMERR: u32 = 0x0A000006;
/// 读文件错误
pub const SAR_READFILEERR: u32 = 0x0A000007;
/// 写文件错误
pub const SAR_WRITEFILEERR: u32 = 0x0A000008;
/// 名称长度错误
pub const SAR_NAMELENERR: u32 = 0x0A000009;
/// 密钥用途错误
pub const SAR_KEYUSAGEERR: u32 = 0x0A00000A;
/// 模的长度错误
pub const SAR_MODULUSLENERR: u32 = 0x0A00000B;
/// 未初始化
pub const SAR_NOTINITIALIZEERR: u32 = 0x0A00000C;
/// 对象错误
pub const SAR_OBJERR: u32 = 0x0A00000D;
/// 内存错误
pub const SAR_MEMORYERR: u32 = 0x0A00000E;
/// 超时
pub const SAR_TIMEOUTERR: u32 = 0x0A00000F;
/// 输入数据长度错误
pub const SAR_INDATALENERR: u32 = 0x0A000010;
/// 输入数据错误
pub const SAR_INDATAERR: u32 = 0x0A000011;
/// 生成随机数错误
pub const SAR_GENRANDERR: u32 = 0x0A000012;
/// HASH对象错
pub const SAR_HASHOBJERR: u32 = 0x0A000013;
/// HASH运算错误
pub const SAR_HASHERR: u32 = 0x0A000014;
/// 产生RSA密钥错
pub const SAR_GENRSAKEYERR: u32 = 0x0A000015;
/// RSA密钥模长错误
pub const SAR_RSAMODULUSLENERR: u32 = 0x0A000016;
/// CSP服务导入公钥错误
pub const SAR_CSPIMPRTPUBKEYERR: u32 = 0x0A000017;
/// RSA加密错误
pub const SAR_RSAENCERR: u32 = 0x0A000018;
/// RSA解密错误
pub const SAR_RSADECERR: u32 = 0x0A000019;
/// HASH值不相等
pub const SAR_HASHNOTEQUALERR: u32 = 0x0A00001A;
/// 密钥未发现
pub const SAR_KEYNOTFOUNTERR: u32 = 0x0A00001B;
/// 证书未发现
pub const SAR_CERTNOTFOUNTERR: u32 = 0x0A00001C;
/// 对象未导出
pub const SAR_NOTEXPORTERR: u32 = 0x0A00001D;
/// 解密时做补丁错误
pub const SAR_DECRYPTPADERR: u32 = 0x0A00001E;
/// MAC长度错误
pub const SAR_MACLENERR: u32 = 0x0A00001F;
/// 缓冲区不足
pub const SAR_BUFFER_TOO_SMALL: u32 = 0x0A000020;
/// 密钥类型错误
pub const SAR_KEYINFOTYPEERR: u32 = 0x0A000021;
/// 无事件错误
pub const SAR_NOT_EVENTERR: u32 = 0x0A000022;
/// 设备已移除
pub const SAR_DEVICE_REMOVED: u32 = 0x0A000023;
/// PIN不正确
pub const SAR_PIN_INCORRECT: u32 = 0x0A000024;
/// PIN被锁死
pub const SAR_PIN_LOCKED: u32 = 0x0A000025;
/// PIN无效
pub const SAR_PIN_INVALID: u32 = 0x0A000026;
/// PIN长度错误
pub const SAR_PIN_LEN_RANGE: u32 = 0x0A000027;
/// 用户已经登录
pub const SAR_USER_ALREADY_LOGGED_IN: u32 = 0x0A000028;
/// 没有初始化用户口令
pub const SAR_USER_PIN_NOT_INITIALIZED: u32 = 0x0A000029;
/// PIN类型错误
pub const SAR_USER_TYPE_INVALID: u32 = 0x0A00002A;
/// 应用名称无效
pub const SAR_APPLICATION_NAME_INVALID: u32 = 0x0A00002B;
/// 应用已经存在
pub const SAR_APPLICATION_EXISTS: u32 = 0x0A00002C;
/// 用户没有登录
pub const SAR_USER_NOT_LOGGED_IN: u32 = 0x0A00002D;
/// 应用不存在
pub const SAR_APPLICATION_NOT_EXISTS: u32 = 0x0A00002E;
/// 文件已经存在
pub const SAR_FILE_ALREADY_EXIST: u32 = 0x0A00002F;
/// 空间不足
pub const SAR_NO_ROOM: u32 = 0x0A000030;
/// 文件不存在
pub const SAR_FILE_NOT_EXIST: u32 = 0x0A000031;
/// 已达到最大可管理容器数
pub const SAR_REACH_MAX_CONTAINER_COUNT: u32 = 0x0A000032;
/// 未通过设备认证
pub const SAR_NO_AUTH: u32 = 0x0A000033;

pub fn get_message(code: u32) -> Option<&'static str> {
    match code {
        SAR_OK => Some("成功"),
        SAR_FAIL => Some("失败"),
        SAR_UNKNOWNERR => Some("异常错误"),
        SAR_NOTSUPPORTYETERR => Some("不支持的服务"),
        SAR_FILEERR => Some("文件操作错误"),
        SAR_INVALIDHANDLEERR => Some("无效的句柄"),
        SAR_INVALIDPARAMERR => Some("无效的参数"),
        SAR_READFILEERR => Some("读文件错误"),
        SAR_WRITEFILEERR => Some("写文件错误"),
        SAR_NAMELENERR => Some("名称长度错误"),
        SAR_KEYUSAGEERR => Some("密钥用途错误"),
        SAR_MODULUSLENERR => Some("模的长度错误"),
        SAR_NOTINITIALIZEERR => Some("未初始化"),
        SAR_OBJERR => Some("对象错误"),
        SAR_MEMORYERR => Some("内存错误"),
        SAR_GENRANDERR => Some("生成随机数错误"),
        SAR_INDATAERR => Some("输入数据错误"),
        SAR_INDATALENERR => Some("输入数据长度错误"),
        SAR_TIMEOUTERR => Some("超时"),
        SAR_HASHOBJERR => Some("HASH运算错误"),
        SAR_HASHERR => Some("HASH值不相等"),
        SAR_KEYNOTFOUNTERR => Some("密钥未发现"),
        SAR_CERTNOTFOUNTERR => Some("证书未发现"),
        SAR_NOTEXPORTERR => Some("对象未导出"),
        SAR_DECRYPTPADERR => Some("解密时做补丁错误"),
        SAR_MACLENERR => Some("MAC长度错误"),
        SAR_BUFFER_TOO_SMALL => Some("缓冲区不足"),
        SAR_KEYINFOTYPEERR => Some("密钥类型错误"),
        SAR_NOT_EVENTERR => Some("无事件错误"),
        SAR_DEVICE_REMOVED => Some("设备已移除"),
        SAR_PIN_INCORRECT => Some("PIN不正确"),
        SAR_PIN_LOCKED => Some("PIN被锁死"),
        SAR_PIN_INVALID => Some("PIN无效"),
        SAR_PIN_LEN_RANGE => Some("PIN长度错误"),
        SAR_USER_ALREADY_LOGGED_IN => Some("用户已经登录"),
        SAR_USER_PIN_NOT_INITIALIZED => Some("没有初始化用户口令"),
        SAR_USER_TYPE_INVALID => Some("PIN类型错误"),
        SAR_APPLICATION_NAME_INVALID => Some("应用名称无效"),
        SAR_APPLICATION_EXISTS => Some("应用已经存在"),
        SAR_USER_NOT_LOGGED_IN => Some("用户没有登录"),
        SAR_APPLICATION_NOT_EXISTS => Some("应用不存在"),
        SAR_FILE_ALREADY_EXIST => Some("文件已经存在"),
        SAR_NO_ROOM => Some("空间不足"),
        SAR_FILE_NOT_EXIST => Some("文件不存在"),
        SAR_REACH_MAX_CONTAINER_COUNT => Some("已达到最大可管理容器数"),
        SAR_NO_AUTH => Some("未通过设备认证"),
        SAR_GENRSAKEYERR => Some("生成RSA密钥错误"),
        SAR_RSAMODULUSLENERR => Some("RSA模的长度错误"),
        SAR_CSPIMPRTPUBKEYERR => Some("CSP服务导入公钥错误"),
        SAR_RSAENCERR => Some("RSA加密错误"),
        SAR_RSADECERR => Some("RSA解密错误"),
        SAR_HASHNOTEQUALERR => Some("HASH值不相等"),
        _ => None,
    }
}
