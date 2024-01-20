use crate::engine;
use crate::SkfCtl;
use libloading::Library;
use std::env;
use std::sync::Arc;

pub(crate) mod skf_ctl;
pub(crate) mod skf_dev;
pub(crate) mod symbol;

pub struct Engine {
    pub(crate) lib: Arc<Library>,
}

impl Engine {
    /// Create new Engine
    ///
    /// [lib] - The library handle
    /// # Example
    /// ```no_run
    /// use skf_rs::Engine;
    /// use skf_rs::LibLoader;
    /// let _ = Engine::new(LibLoader::env_lookup().unwrap());
    /// ```
    pub fn new(lib: Library) -> Self {
        Self { lib: Arc::new(lib) }
    }

    /// Get SkfCtl instance
    pub fn skf_ctl(&self) -> crate::Result<Box<dyn SkfCtl + Send + Sync>> {
        let ctl = engine::skf_ctl::SkfCtlImpl::new(&self.lib)?;
        Ok(Box::new(ctl))
    }

    /// Get SkfCtl instance
    pub fn skf_ctl_arc(&self) -> crate::Result<Arc<dyn SkfCtl + Send + Sync>> {
        let ctl = engine::skf_ctl::SkfCtlImpl::new(&self.lib)?;
        Ok(Arc::new(ctl))
    }
}

pub struct LibLoader;

impl LibLoader {
    pub const ENV_SKF_LIB_FILE: &'static str = "SKF_LIB_FILE";
    pub const ENV_SKF_LIB_NAME: &'static str = "SKF_LIB_NAME";

    /// Load library from environment
    ///
    /// - Look up `SKF_LIB_FILE`, load library from file
    /// - Then,look up `SKF_LIB_NAME` , load library via library name
    pub fn env_lookup() -> crate::Result<Library> {
        use crate::error::Error::Other;
        use anyhow::anyhow;
        if let Some(val) = env::var(Self::ENV_SKF_LIB_FILE).ok() {
            println!("{} detected: {}", Self::ENV_SKF_LIB_FILE, val);
            return Self::of_library_file(&val);
        }
        if let Some(val) = env::var(Self::ENV_SKF_LIB_NAME).ok() {
            println!("{} detected: {}", Self::ENV_SKF_LIB_NAME, val);
            return Self::of_library_name(&val);
        }
        let err = anyhow!(
            "Environment {} or {} not set",
            Self::ENV_SKF_LIB_FILE,
            Self::ENV_SKF_LIB_NAME
        );
        Err(Other(err))
    }

    /// Initialize SkfCtl by loading library
    ///
    /// [name] - The library name,e.g. 'demo'
    pub fn of_library_name(name: impl AsRef<str>) -> crate::Result<Library> {
        use std::ffi::OsStr;
        let file = libloading::library_filename(OsStr::new(name.as_ref()));
        let lib = unsafe { Library::new(&file)? };
        Ok(lib)
    }

    /// Initialize SkfCtl by loading library
    ///
    /// [file] - The library file,e.g. 'demo.dll', 'libdemo.so',
    pub fn of_library_file(file: impl AsRef<str>) -> crate::Result<Library> {
        use std::ffi::OsStr;
        let lib = unsafe { Library::new(OsStr::new(file.as_ref()))? };
        Ok(lib)
    }
}
