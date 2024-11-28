use anyhow::{anyhow, Result};
use libbpf_rs::skel::Skel;

mod bpf {
    include!("bpf/kprobe.skel.rs");
}
use bpf::*;

use crate::workaround::*;

pub(crate) struct KprobeManager<'a> {
    skel: SkelStorage<KprobeSkel<'a>>,
    links: Vec<libbpf_rs::Link>,
}

impl KprobeManager<'_> {
    pub(crate) fn new() -> Result<Self> {
        let mut skel = OpenSkelStorage::new::<KprobeSkelBuilder>()?;

        // Set rodata.
        skel.maps.rodata_data.log_level = 0;

        Ok(Self {
            skel: SkelStorage::load(skel)?,
            links: Vec::new(),
        })
    }

    pub(crate) fn attach(&mut self, probe: &str) -> Result<()> {
        self.links.push(
            self.skel
                .object()
                .progs_mut()
                .find(|p| p.name() == "kprobe_placeholder")
                .ok_or_else(|| anyhow!("Couldn't get program"))?
                .attach_kprobe(false, probe)?,
        );
        Ok(())
    }
}
