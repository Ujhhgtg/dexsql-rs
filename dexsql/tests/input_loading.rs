use std::path::PathBuf;
use std::ptr::NonNull;
use std::sync::Arc;

use dexsql::{DexBytes, DexInput, Engine, EngineOptions};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/dex")
        .join(name)
}

#[test]
fn mixed_inputs_preserve_order_and_external_owner() {
    let storage = Arc::new(std::fs::read(fixture("alpha.dex")).unwrap());
    let lifetime = Arc::downgrade(&storage);
    let address = NonNull::new(storage.as_ptr().cast_mut()).unwrap();
    let bytes = unsafe { DexBytes::from_raw_parts_with_owner(address, storage.len(), storage) };
    let bridge = Engine::open_inputs_with_options(
        vec![
            DexInput::Memory {
                source_name: "loader".into(),
                entry_name: "classes.dex".into(),
                bytes,
            },
            DexInput::Path(fixture("beta.dex")),
        ],
        EngineOptions {
            full_code_items: true,
            ..EngineOptions::default()
        },
    )
    .unwrap();
    let classes = bridge
        .query("SELECT file_id, descriptor FROM classes ORDER BY file_id, descriptor")
        .unwrap();
    assert_eq!(
        classes.rows,
        [
            ["0", "Lfixtures/Alpha;"],
            ["0", "Lfixtures/Gamma;"],
            ["1", "Lfixtures/Beta;"],
        ]
    );
    assert!(lifetime.upgrade().is_some());
    drop(bridge);
    assert!(lifetime.upgrade().is_none());
}

#[test]
fn container_headers_resolve_shared_string_offsets() {
    let mut container = vec![0; 252];
    let total = container.len() as u32;
    for (offset, length) in [(0, 120u32), (120, 132)] {
        container[offset..offset + 8].copy_from_slice(b"dex\n041\0");
        for (field, value) in [
            (32, length),
            (36, 120),
            (40, 0x12345678),
            (56, 1),
            (60, 240),
            (112, total),
            (116, offset as u32),
        ] {
            container[offset + field..offset + field + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    container[240..244].copy_from_slice(&244u32.to_le_bytes());
    container[244..247].copy_from_slice(b"\x01x\0");
    let input = |bytes| DexInput::Memory {
        source_name: "loader".into(),
        entry_name: "container.dex".into(),
        bytes: DexBytes::from_vec(bytes),
    };
    let bridge = Engine::open_inputs(vec![input(container.clone())]).unwrap();
    assert_eq!(bridge.dex_count(), 2);
    let strings = bridge
        .query("SELECT value FROM strings ORDER BY string_pool_id, string_idx")
        .unwrap();
    assert!(strings.rows.iter().all(|row| row == &["x"]));
    assert!(!strings.rows.is_empty());
    container[236] = 0;
    assert!(Engine::open_inputs(vec![input(container)]).is_err());
}
