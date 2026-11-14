use dexsql::{Engine, EngineOptions, IndexNeeds};
use std::path::PathBuf;

fn engine() -> Engine {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex");
    Engine::open_with_options(
        [fixtures.join("alpha.dex"), fixtures.join("beta.dex")],
        EngineOptions {
            index_needs: IndexNeeds::all(),
            eager_code_items: true,
            ..EngineOptions::default()
        },
    )
    .unwrap()
}

#[test]
fn composed_member_sets_preserve_declared_identity_and_multiplicity() {
    let engine = engine();
    let fields = engine.query(
        "SELECT class_descriptor FROM class_fields WHERE field_type='Ljava/lang/String;' GROUP BY class_descriptor HAVING count(*)>=2",
    ).unwrap();
    assert_eq!(fields.rows, vec![vec!["Lfixtures/Alpha;"]]);
    let interfaces = engine.query(
        "SELECT class_descriptor FROM class_interfaces WHERE interface_descriptor='Lfixtures/Gamma;'",
    ).unwrap();
    assert_eq!(interfaces.rows, vec![vec!["Lfixtures/Alpha;"]]);
    let calls = engine.query(
        "SELECT DISTINCT m.descriptor FROM methods m WHERE m.class_descriptor='Lfixtures/Alpha;' AND m.descriptor IN (SELECT c.method FROM method_calls c WHERE c.callee_name='helper' GROUP BY c.method HAVING count(*)>=2) ORDER BY m.descriptor",
    ).unwrap();
    assert_eq!(
        calls.rows,
        vec![vec!["Lfixtures/Alpha;->duplicateInvokes()I"]]
    );
}

#[test]
fn method_prefilters_keep_residual_boolean_and_subquery_semantics() {
    let engine = engine();
    for predicate in [
        "m.param_count=0 AND (m.name='doIt' OR m.name='helper')",
        "m.class_descriptor='Lfixtures/Alpha;' AND m.descriptor IN (SELECT c.method FROM method_calls c WHERE c.callee_name='helper')",
        "m.return_descriptor='I' AND (m.name='helper' OR m.name='missing')",
    ] {
        let optimized = engine.query(&format!(
            "SELECT DISTINCT m.descriptor FROM methods m WHERE {predicate} ORDER BY m.descriptor",
        )).unwrap();
        let unfiltered = engine.query(&format!(
            "SELECT DISTINCT m.descriptor FROM methods m WHERE ({predicate}) OR 0=1 ORDER BY m.descriptor",
        )).unwrap();
        assert_eq!(optimized, unfiltered, "{predicate}");
        assert!(!optimized.rows.is_empty(), "{predicate}");
    }
}

#[test]
fn array_method_references_are_not_dropped_by_membership_prefilters() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/annotated.dex");
    let engine = Engine::open_with_options(
        [fixture],
        EngineOptions {
            index_needs: IndexNeeds::all(),
            eager_code_items: true,
            ..EngineOptions::default()
        },
    )
    .unwrap();
    let methods = engine.query("SELECT DISTINCT m.descriptor FROM methods m WHERE m.descriptor IN (SELECT c.callee FROM method_calls c WHERE c.callee_class='[I') ORDER BY m.descriptor").unwrap();
    assert_eq!(methods.rows, vec![vec!["[I->clone()Ljava/lang/Object;"]]);
    let calls = engine.query("SELECT DISTINCT c.method FROM method_calls c WHERE c.callee IN (SELECT m.descriptor FROM methods m WHERE m.class_descriptor='[I') ORDER BY c.method").unwrap();
    assert_eq!(calls.rows, vec![vec!["Lfixtures/Annotated;->copy([I)[I"]]);
}
