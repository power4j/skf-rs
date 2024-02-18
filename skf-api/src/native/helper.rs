use crate::native::types::{
    DeviceInfo, ECCCipherBlob, ECCPrivateKeyBlob, ECCPublicKeyBlob, ECCSignatureBlob, Version, BYTE,
};

impl Default for DeviceInfo {
    fn default() -> Self {
        Self {
            version: Version::default(),
            manufacturer: [0; 64],
            issuer: [0; 64],
            label: [0; 32],
            serial_number: [0; 32],
            hw_version: Version::default(),
            firmware_version: Version::default(),
            alg_sym_cap: 0,
            alg_asym_cap: 0,
            alg_hash_cap: 0,
            dev_auth_alg_id: 0,
            total_space: 0,
            free_space: 0,
            max_ecc_buffer_size: 0,
            max_buffer_size: 0,
            reserved: [0; 64],
        }
    }
}

impl ECCPublicKeyBlob {
    /// crate `ECCPublicKeyBlob` with 256 bit x and y
    /// ## Panics
    /// this function will panic if `x.len() != 32 || y.len() != 32`
    pub fn new_256(x: &[u8], y: &[u8]) -> Self {
        if x.len() != 32 || y.len() != 32 {
            panic!("x.len() != 32 || y.len() != 32");
        }
        let mut xc = vec![0u8 as BYTE; 32];
        xc.extend(x);
        let mut yc = vec![0u8 as BYTE; 32];
        yc.extend(y);
        Self {
            bit_len: 256,
            x_coordinate: xc.try_into().unwrap(),
            y_coordinate: yc.try_into().unwrap(),
        }
    }
    pub fn x_value(&self) -> &[u8] {
        &self.x_coordinate[self.bit_len as usize / 8..]
    }
    pub fn y_value(&self) -> &[u8] {
        &self.y_coordinate[self.bit_len as usize / 8..]
    }
}

impl ECCPrivateKeyBlob {
    /// crate `ECCPrivateKeyBlob` with 256 key
    /// ## Panics
    /// this function will panic if `key.len() != 32`
    pub fn new_256(key: &[u8]) -> Self {
        if key.len() != 32 {
            panic!("key.len() != 32");
        }
        let mut k = vec![0u8 as BYTE; 32];
        k.extend(key);
        Self {
            bit_len: 256,
            private_key: k.try_into().unwrap(),
        }
    }
}
impl ECCCipherBlob {
    /// cipher filed offset in ECCCipherBlob
    pub const CIPHER_INDEX: usize = std::mem::size_of::<Self>() - 1;

    /// The size of ECCCipherBlob,include dynamic size of cipher
    pub fn size_of(cipher_len: usize) -> usize {
        Self::CIPHER_INDEX + cipher_len
    }

    /// dynamic size of ECCCipherBlob
    #[inline]
    pub fn dst_size(&self) -> usize {
        Self::CIPHER_INDEX + self.cipher_len as usize
    }

    /// raw pointer of cipher filed
    pub fn cipher_ptr(&self) -> *const BYTE {
        self.cipher.as_ptr() as *const BYTE
    }

    /// raw bytes of ECCCipherBlob,include dynamic size of cipher
    ///
    /// # Safety
    ///
    /// This function will copy `cipher_len` bytes data from `cipher` pointer
    pub unsafe fn raw_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(self.dst_size());
        unsafe {
            std::ptr::copy(
                self.x_coordinate.as_ptr() as *const u8,
                v.as_mut_ptr(),
                Self::CIPHER_INDEX,
            );
            std::ptr::copy(
                self.cipher.as_ptr(),
                v.as_mut_ptr().offset(Self::CIPHER_INDEX as isize),
                self.cipher_len as usize,
            );
            v.set_len(self.dst_size());
        }
        v
    }
}

impl Default for ECCSignatureBlob {
    fn default() -> Self {
        Self {
            r: [0u8; 64],
            s: [0u8; 64],
        }
    }
}
#[cfg(test)]
mod test {
    use crate::native::types::{
        ECCCipherBlob, BYTE, ECC_MAX_X_COORDINATE_BITS_LEN, ECC_MAX_Y_COORDINATE_BITS_LEN, ULONG,
    };

    #[test]
    fn cipher_blob_layout_test() {
        #[derive(Debug, Copy, Clone)]
        #[repr(C, packed(1))]
        struct SizedBlob<const SIZE: usize> {
            pub x_coordinate: [BYTE; ECC_MAX_X_COORDINATE_BITS_LEN / 8],
            pub y_coordinate: [BYTE; ECC_MAX_Y_COORDINATE_BITS_LEN / 8],
            pub hash: [BYTE; 32],
            pub cipher_len: ULONG,
            pub cipher: [BYTE; SIZE],
        }

        let x = SizedBlob::<100> {
            x_coordinate: [1u8; 64],
            y_coordinate: [2u8; 64],
            hash: [3u8; 32],
            cipher_len: 100,
            cipher: [4u8; 100],
        };
        let blob: *const SizedBlob<100> = &x;
        let blob = unsafe { &*(blob as *const ECCCipherBlob) };

        assert_eq!(blob.x_coordinate, [1u8; 64]);
        assert_eq!(blob.y_coordinate, [2u8; 64]);
        assert_eq!(blob.hash, [3u8; 32]);
        assert_eq!(
            unsafe { std::ptr::addr_of!(blob.cipher_len).read_unaligned() },
            100
        );
        assert_eq!(blob.cipher, [4u8; 1]);

        let bytes = unsafe { blob.raw_bytes() };
        assert_eq!(bytes.len(), blob.dst_size());
        println!("raw bytes of ECCCipherBlob = {:?}", bytes);
    }
}
