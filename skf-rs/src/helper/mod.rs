pub mod auth;
pub mod easy;

pub mod mem {
    use crate::{ECCEncryptedData, EnvelopedKeyData};

    use skf_api::native::types::ECCPublicKeyBlob;
    use std::cmp::min;
    use std::ffi::CStr;
    use std::slice;

    /// Returns the position of the first null byte
    ///
    /// [ptr] - The pointer to the buffer
    ///
    /// [len] - The length of the buffer
    ///
    /// # Examples
    /// ```
    /// use skf_rs::helper::mem::first_null_byte;
    /// let ptr = b"Hello\0World\0".as_ptr();
    /// unsafe {
    ///     assert_eq!(Some(5), first_null_byte(ptr, 12));
    ///     assert_eq!(None, first_null_byte(ptr, 5));
    ///     assert_eq!(Some(4), first_null_byte(ptr.add(1), 11));
    ///     assert_eq!(Some(0), first_null_byte(ptr.add(5), 7));
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub unsafe fn first_null_byte(ptr: *const u8, len: usize) -> Option<usize> {
        let slice = unsafe { slice::from_raw_parts(ptr, len) };
        slice.iter().position(|&x| x == 0)
    }

    /// Returns the position of the first two null byte
    ///
    /// [ptr] - The pointer to the buffer
    ///
    /// [len] - The length of the buffer
    ///
    /// # Examples
    /// ```
    /// use skf_rs::helper::mem::first_two_null_byte;
    /// let ptr = b"Hello\0World\0\0".as_ptr();
    /// unsafe {
    ///     assert_eq!(Some(12), first_two_null_byte(ptr, 13));
    ///     assert_eq!(Some(11), first_two_null_byte(ptr.add(1), 12));
    ///     assert_eq!(None, first_two_null_byte(ptr, 12));
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub const unsafe fn first_two_null_byte(ptr: *const u8, len: usize) -> Option<usize> {
        let mut pos = 0;
        while pos < len {
            if *ptr.add(pos) == 0 && pos + 1 < len && *ptr.add(pos + 1) == 0 {
                return Some(pos + 1);
            }
            pos += 1;
        }
        None
    }

    /// Parse a C string from buffer
    ///
    /// [ptr] - The pointer to the buffer
    ///
    /// [len] - The length of the buffer
    /// # Examples
    /// ```
    /// use std::ffi::CStr;
    /// use skf_rs::helper::mem::parse_cstr;
    /// let ptr = b"Hello\0World\0".as_ptr();
    /// unsafe {
    ///     assert_eq!(Some(CStr::from_bytes_with_nul(b"Hello\0").unwrap()), parse_cstr(ptr, 12));
    ///     assert_eq!(Some(CStr::from_bytes_with_nul(b"lo\0").unwrap()), parse_cstr(ptr.add(3), 12));
    ///     assert_eq!(Some(CStr::from_bytes_with_nul(b"World\0").unwrap()), parse_cstr(ptr.add(6), 12));
    ///     assert_eq!(Some(CStr::from_bytes_with_nul(b"\0").unwrap()), parse_cstr(ptr.add(5), 1));
    ///     assert_eq!(None, parse_cstr(ptr, 1));
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub unsafe fn parse_cstr<'a>(ptr: *const u8, len: usize) -> Option<&'a CStr> {
        let slice = unsafe { slice::from_raw_parts(ptr, len) };
        CStr::from_bytes_until_nul(slice).ok()
    }

    /// Parse a C string from buffer, use `CStr::to_string_lossy` to convert data
    ///
    /// [ptr] - The pointer to the buffer
    ///
    /// [len] - The length of the buffer
    #[must_use]
    pub unsafe fn parse_cstr_lossy(ptr: *const u8, len: usize) -> Option<String> {
        let val = unsafe { parse_cstr(ptr, len) };
        val.map(|s| s.to_string_lossy().to_string())
    }

    /// Parse C string list from buffer, the list may end with two null byte
    ///
    /// [ptr] - The pointer to the buffer
    ///
    /// [len] - The length of the buffer
    /// # Examples
    /// ```
    /// use std::ffi::CStr;
    /// use skf_rs::helper::mem::parse_cstr_list;
    /// unsafe {
    ///     let list = parse_cstr_list(b"Hello\0World\0\0".as_ptr(), 13);
    ///     assert_eq!(CStr::from_bytes_with_nul(b"Hello\0").unwrap(), *list.get(0).unwrap());
    ///     assert_eq!(CStr::from_bytes_with_nul(b"World\0").unwrap(), *list.get(1).unwrap());
    ///
    ///     let list = parse_cstr_list(b"Hello\0World\0".as_ptr(), 12);
    ///     assert_eq!(CStr::from_bytes_with_nul(b"Hello\0").unwrap(), *list.get(0).unwrap());
    ///     assert_eq!(CStr::from_bytes_with_nul(b"World\0").unwrap(), *list.get(1).unwrap());
    ///
    ///     let list = parse_cstr_list(b"Hello\0World".as_ptr(), 11);
    ///     assert_eq!(CStr::from_bytes_with_nul(b"Hello\0").unwrap(), *list.get(0).unwrap());
    ///
    ///     let list = parse_cstr_list(b"Hello".as_ptr(), 5);
    ///     assert!(list.is_empty());
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub unsafe fn parse_cstr_list<'a>(ptr: *const u8, len: usize) -> Vec<&'a CStr> {
        let mut list: Vec<&CStr> = Vec::new();
        let mut next_str = 0;
        let mut pos = 0;
        while pos < len {
            if *ptr.add(pos) == 0 {
                let bytes = slice::from_raw_parts(ptr.add(next_str), pos - next_str + 1);
                list.push(CStr::from_bytes_with_nul_unchecked(bytes));
                next_str = pos + 1;
                if next_str < len && *ptr.add(next_str) == 0 {
                    break;
                }
            }
            pos += 1;
        }
        list
    }

    /// Parse C string list from buffer, the list may end with two null byte
    ///
    /// [ptr] - The pointer to the buffer
    ///
    /// [len] - The length of the buffer
    #[must_use]
    pub unsafe fn parse_cstr_list_lossy(ptr: *const u8, len: usize) -> Vec<String> {
        let list = unsafe { parse_cstr_list(ptr, len) };
        list.iter()
            .map(|s| s.to_string_lossy().to_string())
            .collect()
    }

    /// Write string to buffer
    ///
    /// [src] - The string to write,if too long, it will be truncated
    ///
    /// [buffer] - The buffer to write to,at least one byte to fill with null byte
    ///
    /// ## Memory copy
    ///
    /// - if the string is too long,it will be truncated,and the last byte will be set to null byte
    /// - if the string is smaller than the buffer size,it will be filled with null byte
    ///
    /// ## example
    /// ```
    /// use skf_rs::helper::mem::write_cstr;
    ///
    /// let mut buffer = [0u8; 11];
    /// unsafe {
    ///     write_cstr("Hello World", &mut buffer);
    ///}
    ///assert_eq!(b"Hello Worl\0", &buffer);
    ///```
    pub unsafe fn write_cstr(src: impl AsRef<str>, buffer: &mut [u8]) {
        let src = src.as_ref().as_bytes();
        let len = min(src.len(), buffer.len());
        debug_assert!(len > 0);
        unsafe {
            std::ptr::copy(src.as_ptr(), buffer.as_mut_ptr(), len);
        }
        if len < buffer.len() {
            buffer[len] = 0;
        } else {
            buffer[len - 1] = 0;
        }
    }

    /// Write string to buffer
    ///
    /// [src] - The string to write
    ///
    /// [buffer_ptr] - The buffer to write to
    ///
    /// [buffer_len] - The length of the buffer
    pub unsafe fn write_cstr_ptr(src: impl AsRef<str>, buffer_ptr: *mut u8, buffer_len: usize) {
        let bytes = slice::from_raw_parts_mut(buffer_ptr, buffer_len);
        write_cstr(src, bytes);
    }

    impl ECCEncryptedData {
        /// Convert to bytes of `ECCCipherBlob`
        pub fn blob_bytes(&self) -> Vec<u8> {
            use skf_api::native::types::ULONG;

            let len = 64 + 64 + 32 + 4 + self.cipher.len();
            let mut vec: Vec<u8> = Vec::with_capacity(len);
            let cipher_len: [u8; 4] = (self.cipher.len() as ULONG).to_ne_bytes();
            vec.extend_from_slice(&self.ec_x);
            vec.extend_from_slice(&self.ec_y);
            vec.extend_from_slice(&self.hash);
            vec.extend_from_slice(&cipher_len);
            vec.extend_from_slice(&self.cipher);
            vec
        }
    }

    impl EnvelopedKeyData {
        /// Convert to bytes of `EnvelopedKeyBlob`
        pub fn blob_bytes(&self) -> Vec<u8> {
            use skf_api::native::types::ULONG;

            let cipher_blob = self.ecc_cipher.blob_bytes();
            let len = 4 + 4 + 4 + 64 + std::mem::size_of::<ECCPublicKeyBlob>() + cipher_blob.len();
            let mut vec: Vec<u8> = Vec::with_capacity(len);

            // version
            let bytes: [u8; 4] = (self.version as ULONG).to_ne_bytes();
            vec.extend_from_slice(&bytes);
            // sym_alg_id
            let bytes: [u8; 4] = (self.sym_alg_id as ULONG).to_ne_bytes();
            vec.extend_from_slice(&bytes);
            // bits
            let bytes: [u8; 4] = (self.bits as ULONG).to_ne_bytes();
            vec.extend_from_slice(&bytes);
            // encrypted_pri_key
            vec.extend_from_slice(&self.encrypted_pri_key);

            // pub_key.bit_len
            let bytes: [u8; 4] = (self.pub_key.bit_len as ULONG).to_ne_bytes();
            vec.extend_from_slice(&bytes);

            // pub_key.x_coordinate
            vec.extend_from_slice(&self.pub_key.x_coordinate);

            // pub_key.y_coordinate
            vec.extend_from_slice(&self.pub_key.y_coordinate);

            // cipher
            vec.extend_from_slice(&cipher_blob);
            vec
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::ECCEncryptedData;

        #[test]
        fn parse_terminated_cstr_list_test() {
            unsafe {
                let list = parse_cstr_list(b"Hello\0\0".as_ptr(), 7);
                assert_eq!(1, list.len());

                let list = parse_cstr_list(b"Hello\0World\0\0".as_ptr(), 13);
                assert_eq!(
                    CStr::from_bytes_with_nul(b"Hello\0").unwrap(),
                    *list.first().unwrap()
                );
                assert_eq!(
                    CStr::from_bytes_with_nul(b"World\0").unwrap(),
                    *list.get(1).unwrap()
                );
            }
        }
        #[test]
        fn write_cstr_test() {
            let input = "Hello World";
            let mut buffer = [0u8; 12];
            unsafe {
                write_cstr(input, &mut buffer);
            }
            assert_eq!(b"Hello World\0", &buffer);

            let mut buffer = [0u8; 11];
            unsafe {
                write_cstr(input, &mut buffer);
            }
            assert_eq!(b"Hello Worl\0", &buffer);

            let mut buffer = [0u8; 1];
            unsafe {
                write_cstr(input, &mut buffer);
            }
            assert_eq!(b"\0", &buffer);
        }

        #[test]
        fn cipher_blob_data_test() {
            use skf_api::native::types::ECCCipherBlob;
            let data = ECCEncryptedData {
                ec_x: [1u8; 64],
                ec_y: [2u8; 64],
                hash: [3u8; 32],
                cipher: vec![1u8, 2u8, 3u8, 4u8, 5u8],
            };
            let mem = data.blob_bytes();
            assert_eq!(mem.len(), 64 + 64 + 32 + 4 + 5);
            unsafe {
                let blob_ptr = mem.as_ptr() as *const ECCCipherBlob;
                let blob = &*blob_ptr;

                assert_eq!(blob.x_coordinate, [1u8; 64]);
                assert_eq!(blob.y_coordinate, [2u8; 64]);
                assert_eq!(blob.hash, [3u8; 32]);
                assert_eq!(std::ptr::addr_of!(blob.cipher_len).read_unaligned(), 5);
                assert_eq!(blob.cipher, [1u8]);
            }
        }
    }
}

pub mod param {
    use crate::error::InvalidArgumentError;
    use crate::Result;
    use std::ffi::CString;

    /// Convert `&str` to `CString`
    ///
    /// ## Errors
    /// This function will return an error if conversion from `&str` to `CString` fails,The error message use `param_name` to describe the parameter.
    pub fn as_cstring(
        param_name: impl AsRef<str>,
        param_value: impl AsRef<str>,
    ) -> Result<CString> {
        let value = CString::new(param_value.as_ref()).map_err(|e| {
            InvalidArgumentError::new(
                format!("parameter '{}' is invalid", param_name.as_ref()),
                Some(anyhow::Error::new(e)),
            )
        })?;
        Ok(value)
    }
}
