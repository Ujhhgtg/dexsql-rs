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

#[test]
fn indexed_membership_scans_preserve_rows_duplicates_and_order() {
    let engine = engine();
    for (table, projection, predicates) in [
        ("methods", "file_id,method_idx,descriptor", vec![
            "name='helper' OR name='fieldTraffic'",
            "class_descriptor IN (SELECT descriptor FROM classes WHERE descriptor='Lfixtures/Alpha;') AND return_descriptor='I'",
            "descriptor IN (SELECT callee FROM method_calls WHERE callee_name='helper') OR descriptor IN (SELECT method FROM method_calls WHERE callee_name='helper')",
        ]),
        ("class_methods", "file_id,class_idx,method_idx,method_descriptor", vec![
            "method_descriptor IN (SELECT descriptor FROM methods WHERE name='helper') OR method_descriptor IN (SELECT descriptor FROM methods WHERE name='fieldTraffic')",
            "class_descriptor='Lfixtures/Alpha;' AND method_name='helper'",
        ]),
        ("class_fields", "file_id,class_idx,field_idx,field_descriptor", vec![
            "field_type='Ljava/lang/String;' OR field_type='I'",
            "field_name='name' AND class_descriptor='Lfixtures/Alpha;'",
            "field_descriptor IN (SELECT descriptor FROM fields WHERE name='name')",
        ]),
        ("method_field_accesses", "file_id,method_idx,field_idx,using_type", vec![
            "method IN (SELECT descriptor FROM methods WHERE name='fieldTraffic')",
            "field IN (SELECT descriptor FROM fields WHERE name='name')",
            "method IN (SELECT descriptor FROM methods WHERE name='fieldTraffic') AND field IN (SELECT descriptor FROM fields WHERE name='name')",
        ]),
    ] {
        for predicate in predicates {
            for limit in ["", " LIMIT 2 OFFSET 1"] {
                let actual = engine.query(&format!("SELECT {projection} FROM {table} WHERE {predicate}{limit}")).unwrap();
                let expected = engine.query(&format!("SELECT {projection} FROM {table} WHERE ({predicate}) OR 0=1{limit}")).unwrap();
                assert_eq!(actual, expected, "{table}: {predicate}{limit}");
                if limit.is_empty() { assert!(!actual.rows.is_empty(), "{table}: {predicate}"); }
            }
        }
    }
}

#[test]
fn candidate_reduction_preserves_group_counts_and_inner_limits() {
    let engine = engine();
    for predicate in [
        "m.class_descriptor='Lfixtures/Alpha;' AND m.descriptor IN (SELECT c.method FROM method_calls c GROUP BY c.method HAVING count(*)>=2)",
        "m.class_descriptor='Lfixtures/Alpha;' AND m.descriptor IN (SELECT c.method FROM method_calls c GROUP BY c.method,c.callee HAVING count(*)>=2)",
        "m.name='duplicateInvokes' AND m.descriptor IN (SELECT c.method FROM method_calls c ORDER BY c.method DESC LIMIT 1)",
        "m.name='helper' AND m.descriptor NOT IN (SELECT NULL FROM method_calls)",
        "m.name='helper' AND m.descriptor NOT IN (SELECT c.callee FROM method_calls c WHERE c.callee_name='absent')",
        "m.name='helper' AND m.descriptor IN (SELECT c.callee FROM method_calls c UNION SELECT NULL)",
    ] {
        let actual = engine.query(&format!("SELECT m.descriptor FROM methods m WHERE {predicate} ORDER BY m.descriptor")).unwrap();
        let expected = engine.query(&format!("SELECT m.descriptor FROM methods m WHERE ({predicate}) OR 0=1 ORDER BY m.descriptor")).unwrap();
        assert_eq!(actual, expected, "{predicate}");
    }
    let result = engine.query("SELECT m.descriptor FROM methods m WHERE m.name='duplicateInvokes' AND m.descriptor IN (SELECT c.method FROM method_calls c GROUP BY c.method HAVING count(*)>=2)").unwrap();
    assert_eq!(
        result.rows,
        vec![vec!["Lfixtures/Alpha;->duplicateInvokes()I"]]
    );
}

#[test]
fn method_candidate_indexes_are_optional() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/alpha.dex");
    let indexed = engine();
    let unindexed = Engine::open([fixture]).unwrap();
    for predicate in [
        "name='helper'",
        "class_descriptor='Lfixtures/Alpha;'",
        "return_descriptor='I' AND param_count=0",
        "descriptor='Lfixtures/Alpha;->helper()I'",
        "descriptor IN (SELECT descriptor FROM methods WHERE name='helper')",
    ] {
        let sql = format!("SELECT DISTINCT descriptor FROM methods WHERE class_descriptor='Lfixtures/Alpha;' AND ({predicate}) ORDER BY descriptor");
        let actual = unindexed.query(&sql).unwrap();
        assert_eq!(actual, indexed.query(&sql).unwrap(), "{predicate}");
        assert!(!actual.rows.is_empty());
    }
}
