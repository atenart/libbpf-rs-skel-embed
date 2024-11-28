use std::mem::MaybeUninit;

use anyhow::{anyhow, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};

mod bpf {
    include!("bpf/kprobe.skel.rs");
}
use bpf::*;

pub(crate) struct KprobeManager<'a> {
    storage: Box<MaybeUninit<libbpf_rs::OpenObject>>,
    skel: KprobeSkel<'a>,
    links: Vec<libbpf_rs::Link>,
}

impl KprobeManager<'_> {
    pub(crate) fn new() -> Result<Self> {
        let mut storage = Box::new(MaybeUninit::uninit());
        let skel = KprobeSkelBuilder::default().open(&mut storage)?;

        // Set rodata.
        skel.maps.rodata_data.log_level = 0;

        Ok(Self {
            storage,
            skel: skel.load()?,
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
