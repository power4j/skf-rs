[![crates.io version badge](https://img.shields.io/crates/v/skf-rs?label=skf-rs)](https://crates.io/crates/skf-rs)
[![Documentation](https://docs.rs/skf-rs/badge.svg)](https://docs.rs/skf-rs)

Rust wrapper for GM/T 0016-2012(Smart token cryptography application interface specification).


# Usage

Listing available device:

```rust
use skf_rs::{Engine, LibLoader};

fn main() {
    let engine = Engine::new(LibLoader::env_lookup().unwrap());
    let manager = engine.device_manager().unwrap();
    let list = manager.enum_device(true).unwrap();
    list.iter().for_each(|name| println!("{}", name));
}

```

# Examples

There are several included examples, which help demonstrate the functionality of this library and
can help debug software or hardware errors.

# Native Dependencies

To run the examples (or your application build on this library),The vendor library must be installed.The `LibLoader` load the library dynamically.


# Resources

- [libloading](https://docs.rs/libloading/latest/libloading/)