use super::*;
/// Typed settings and callbacks published during plugin initialization.
///
/// Registration is complete before requests begin; readers share immutable
/// values rather than interpreting configuration through JSON metadata.
#[derive(Clone, Default)]
pub struct ContextExtensions(HashMap<TypeId, Arc<dyn Any + Send + Sync>>);

impl ContextExtensions {
    pub fn insert<T: Any + Send + Sync>(&mut self, value: T) {
        drop(self.0.insert(TypeId::of::<T>(), Arc::new(value)));
    }

    #[must_use]
    pub fn get<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        Arc::clone(self.0.get(&TypeId::of::<T>())?).downcast().ok()
    }
}

impl std::fmt::Debug for ContextExtensions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContextExtensions").finish_non_exhaustive()
    }
}
