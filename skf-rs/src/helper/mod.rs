pub mod mem {
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
            if *ptr.add(pos) == 0 {
                if pos + 1 < len && *ptr.add(pos + 1) == 0 {
                    return Some(pos + 1);
                }
            }
            pos = pos + 1;
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
            pos = pos + 1;
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
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_terminated_cstr_list_test() {
            unsafe {
                let list = parse_cstr_list(b"Hello\0\0".as_ptr(), 7);
                assert_eq!(1, list.len());

                let list = parse_cstr_list(b"Hello\0World\0\0".as_ptr(), 13);
                assert_eq!(
                    CStr::from_bytes_with_nul(b"Hello\0").unwrap(),
                    *list.get(0).unwrap()
                );
                assert_eq!(
                    CStr::from_bytes_with_nul(b"World\0").unwrap(),
                    *list.get(1).unwrap()
                );
            }
        }
    }
}