//! GM/T 0016-2012 types

use std::ffi;

type INT8 = i8;
type INT16 = i16;
type INT32 = i32;
type SHORT = INT16;
type LONG = INT32;
type UINT8 = u8;
type UINT16 = u16;
type UINT32 = u32;
type UINT = INT32;
type USHORT = UINT16;
type ULONG = UINT32;

type BOOL = bool;
type BYTE = UINT8;
type CHAR = UINT8;

type WORD = UINT16;

type DWORD = UINT32;
type FLAGS = UINT32;

type LPSTR = *const CHAR;
type HANDLE = ffi::c_void;
type HAPPLICATION = HANDLE;
type HCONTAINER = HANDLE;

/// Version
#[derive(Debug, Copy, Clone)]
#[repr(C)]
#[repr(align(1))]
pub struct Version {
    pub major: BYTE,
    pub minor: BYTE,
}
