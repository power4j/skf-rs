use skf_api;

pub fn version() -> String {
    let version = skf_api::skf::types::Version { major: 0, minor: 1 };
    format!("{}.{}", version.major, version.minor)
}
