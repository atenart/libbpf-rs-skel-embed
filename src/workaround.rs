/// Code taken from https://github.com/retis-org/retis/pull/441
use std::{
    mem::{transmute, ManuallyDrop, MaybeUninit},
    ops::{Deref, DerefMut},
};

use anyhow::Result;

/// Holds an open skeleton and its storage.
pub(crate) struct OpenSkelStorage<T> {
    storage: ManuallyDrop<Box<MaybeUninit<libbpf_rs::OpenObject>>>,
    skel: ManuallyDrop<T>,
}

impl<'a, T> OpenSkelStorage<T> {
    /// Creates a new OpenSkelStorage<T> where T is the output of a SkelBuilder
    /// implementation, aka. an open skeleton.
    ///
    /// When creating an open skeleton, libbpf_rs requires to provide storage
    /// for the underlying open object. This storage will be used for its entire
    /// lifetime, including when being loaded and transformed to an object.
    ///
    /// Because of this, to allow embedding an open skeleton in an internal
    /// structure we need a little dance as Rust does not allow self
    /// referencing. Also the storage must live the entire time the object is
    /// alive and it must be kept in the same memory place.
    ///
    /// 1. The storage must be boxed so it can be moved later on when the open
    ///    skeleton (open object) is loaded and transformed to a skeleton
    ///    (object).
    /// 2. Both the storage and the skeleton must not be dropped automatically,
    ///    as the order matters.
    /// 3. The lifetime of the skeleton must be faked to being 'static for
    ///    self-referencing to work. For this we actually trick Rust into seeing
    ///    the storage reference to be 'static, which in turns will make the
    ///    skeleton builder to issue an open skeleton as follow:
    ///    OpenSkel<'static>. All subsequent objects generated by the open
    ///    skeleton will in turn be 'static.
    ///
    /// Note that for all this to work, we do not implement Drop for this type.
    /// As such, it *must* be consumed by SkelStorage::load().
    pub(crate) fn new<B>() -> Result<Self>
    where
        B: libbpf_rs::skel::SkelBuilder<'a, Output = T> + Default,
    {
        let mut storage = ManuallyDrop::new(Box::new(MaybeUninit::uninit()));
        let r#ref = unsafe {
            transmute::<
                &mut ManuallyDrop<Box<MaybeUninit<libbpf_rs::OpenObject>>>,
                &'static mut ManuallyDrop<Box<MaybeUninit<libbpf_rs::OpenObject>>>,
            >(&mut storage)
        };

        let skel = ManuallyDrop::new(B::default().open(r#ref)?);
        Ok(Self { storage, skel })
    }
}

impl<T> Deref for OpenSkelStorage<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.skel
    }
}

impl<T> DerefMut for OpenSkelStorage<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.skel
    }
}

/// Holds a skeleton and its storage.
pub(crate) struct SkelStorage<T> {
    storage: ManuallyDrop<Box<MaybeUninit<libbpf_rs::OpenObject>>>,
    skel: ManuallyDrop<T>,
}

impl<'a, T> SkelStorage<T> {
    pub(crate) fn load<O>(from: OpenSkelStorage<O>) -> Result<SkelStorage<T>>
    where
        O: libbpf_rs::skel::OpenSkel<'a, Output = T>,
    {
        let skel = ManuallyDrop::into_inner(from.skel);
        let storage = ManuallyDrop::into_inner(from.storage);

        Ok(SkelStorage {
            storage: ManuallyDrop::new(storage),
            skel: ManuallyDrop::new(skel.load()?),
        })
    }
}

impl<T> Deref for SkelStorage<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.skel
    }
}

impl<T> DerefMut for SkelStorage<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.skel
    }
}

impl<T> Drop for SkelStorage<T> {
    fn drop(&mut self) {
        unsafe {
            ManuallyDrop::drop(&mut self.skel);
            ManuallyDrop::drop(&mut self.storage);
        }
    }
}
