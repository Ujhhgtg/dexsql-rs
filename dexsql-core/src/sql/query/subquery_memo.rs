use super::*;

#[derive(Debug, Default)]
pub(super) struct Memo {
    values: RefCell<HashMap<String, Arc<membership::Values>>>,
    bytes: Cell<u64>,
    depth: Cell<usize>,
}

pub(super) struct Scope<'a>(&'a Memo);

impl Memo {
    pub(super) fn scope(&self) -> Scope<'_> {
        self.depth.set(self.depth.get() + 1);
        Scope(self)
    }

    pub(super) fn clear(&self) {
        self.values.borrow_mut().clear();
        self.bytes.set(0);
    }

    pub(super) fn get(&self, sql: &str) -> Option<Arc<membership::Values>> {
        self.values.borrow().get(sql).cloned()
    }

    pub(super) fn insert(&self, sql: String, values: Arc<membership::Values>, bytes: u64) {
        let retained = self
            .bytes
            .get()
            .saturating_add(bytes)
            .saturating_add(sql.len() as u64 + 128);
        if retained <= 8 * 1024 * 1024 {
            self.values.borrow_mut().insert(sql, values);
            self.bytes.set(retained);
        }
    }
}

impl Drop for Scope<'_> {
    fn drop(&mut self) {
        self.0.depth.set(self.0.depth.get() - 1);
        if self.0.depth.get() == 0 {
            self.0.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memo_is_shared_only_within_its_query_and_obeys_its_budget() {
        let memo = Memo::default();
        {
            let _outer = memo.scope();
            let values = Arc::new(membership::Values::default());
            memo.insert("SELECT 1".to_owned(), values.clone(), 64);
            {
                let _inner = memo.scope();
                assert!(Arc::ptr_eq(&values, &memo.get("SELECT 1").unwrap()));
                memo.insert("SELECT 2".to_owned(), values, 8 * 1024 * 1024);
                assert!(memo.get("SELECT 2").is_none());
            }
            assert!(memo.get("SELECT 1").is_some());
        }
        assert!(memo.get("SELECT 1").is_none());
        assert_eq!(memo.bytes.get(), 0);
    }
}
