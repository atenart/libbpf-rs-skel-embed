use anyhow::Result;

mod manager;
use manager::*;

mod workaround;

fn main() -> Result<()> {
    let mut mgr = KprobeManager::new()?;

    mgr.attach("pskb_expand_head")?;
    mgr.attach("kfree_skb_partial")?;

    std::thread::sleep(std::time::Duration::from_secs(10));

    Ok(())
}
