use crate::engine::symbol::ModCtl;
use std::fmt::Debug;
use std::sync::Arc;

pub(crate) struct SkfAppImpl {
    lib: Arc<libloading::Library>,
    symbols: ModCtl,
}

impl SkfAppImpl {
    /// Initialize
    ///
    /// [lib] - The library handle
    pub fn new(lib: &Arc<libloading::Library>) -> crate::Result<Self> {
        let lc = Arc::clone(lib);
        let symbols = ModCtl::load_symbols(lib)?;
        Ok(Self { lib: lc, symbols })
    }
}

impl Debug for SkfAppImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SkfAccessImpl")
    }
}
