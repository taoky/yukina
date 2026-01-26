use super::Extension;

#[derive(Debug, Default)]
pub struct FreeBSDPkg {}

impl Extension for FreeBSDPkg {
    fn name(&self) -> &'static str {
        "freebsd-pkg"
    }

    /* no-op for compatibility */
}
