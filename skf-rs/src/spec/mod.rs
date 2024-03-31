pub mod algorithm {
    pub const SGD_3DES_ECB: u32 = 0x00000001;

    pub const SGD_3DES_CBC: u32 = 0x00000002;

    pub const SGD_3DES_CFB: u32 = 0x00000004;

    pub const SGD_3DES_OFB: u32 = 0x00000008;

    pub const SGD_3DES_MAC: u32 = 0x00000010;

    pub const SGD_SM1_ECB: u32 = 0x00000101;

    pub const SGD_SM1_CBC: u32 = 0x00000102;

    pub const SGD_SM1_CFB: u32 = 0x00000104;

    pub const SGD_SM1_OFB: u32 = 0x00000108;

    pub const SGD_SM1_MAC: u32 = 0x00000110;

    pub const SGD_SSF33_ECB: u32 = 0x00000201;

    pub const SGD_SSF33_CBC: u32 = 0x00000202;

    pub const SGD_SSF33_CFB: u32 = 0x00000204;

    pub const SGD_SSF33_OFB: u32 = 0x00000208;

    pub const SGD_SSF33_MAC: u32 = 0x00000210;

    pub const SGD_SM4_ECB: u32 = 0x00000401;

    pub const SGD_SM4_CBC: u32 = 0x00000402;

    pub const SGD_SMS4_CFB: u32 = 0x00000404;

    pub const SGD_SMS4_OFB: u32 = 0x00000408;

    pub const SGD_SMS4_MAC: u32 = 0x00000410;

    pub const SGD_RSA: u32 = 0x00010000;

    /// SM2 ECC
    pub const SGD_SM2: u32 = 0x00020100;

    /// SM2 ECC(Sign)

    pub const SGD_SM2_1: u32 = 0x00020200;
    /// SM2 ECC(key exchange)

    pub const SGD_SM2_2: u32 = 0x00020400;

    /// SM2 ECC(encryption)
    pub const SGD_SM2_3: u32 = 0x00020800;

    pub const SGD_SM3: u32 = 0x00000001;

    pub const SGD_SHA1: u32 = 0x00000002;

    pub const SGD_SHA256: u32 = 0x00000004;
}
