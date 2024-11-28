use anyhow::{anyhow, Result};
use libbpf_rs::skel::SkelBuilder;

mod bpf {
    include!("bpf/kprobe.skel.rs");
}
use bpf::*;

pub(crate) struct KprobeManager {
    obj: libbpf_rs::Object,
    links: Vec<libbpf_rs::Link>,
}

impl KprobeManager {
    pub(crate) fn new() -> Result<Self> {
        let mut skel = KprobeSkelBuilder::default().open()?;

        // Set rodata.
        skel.rodata_mut().log_level = 0;

        Ok(Self {
            obj: skel.obj.load()?,
            links: Vec::new(),
        })
    }

    pub(crate) fn attach(&mut self, probe: &str) -> Result<()> {
        self.links.push(
            self.obj.prog_mut("kprobe_placeholder")
                .ok_or_else(|| anyhow!("Couldn't get program"))?
                .attach_kprobe(false, probe)?,
        );
        Ok(())
    }
}
