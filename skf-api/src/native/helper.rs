use crate::native::types::{DeviceInfo, FileAttribute, Version};

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

