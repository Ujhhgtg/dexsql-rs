use super::*;

#[test]
#[ignore = "requires DEXSQL_QUERY_AUDIT pointing to extracted query JSON"]
fn extracted_descriptor_queries_use_bounded_plans() {
    let path = std::env::var("DEXSQL_QUERY_AUDIT").unwrap();
    let queries: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let dataset = if let Ok(apk) = std::env::var("DEXSQL_QUERY_AUDIT_APK") {
        Dataset::load_paths(&[PathBuf::from(apk)]).unwrap()
    } else {
        Dataset::default()
    };
    let mut unsupported = Vec::new();
    for query in queries.as_array().unwrap() {
        let sql = query["sql"].as_str().unwrap();
        let started = std::time::Instant::now();
        match fast_descriptor::try_fast_descriptor_lookup(&parse(sql), &dataset, None) {
            None => unsupported.push(format!("{}: {sql}", query["id"])),
            Some(result) => {
                let result = result.unwrap();
                eprintln!(
                    "{} {}ms {} rows",
                    query["id"],
                    started.elapsed().as_millis(),
                    result.rows.len()
                );
                println!(
                    "{}",
                    serde_json::json!({"id": query["id"], "columns": result.columns, "rows": result.rows})
                );
            }
        }
    }
    for file in &dataset.files {
        for (kind, descriptors) in [
            ("methods", &file.method_descriptors),
            ("fields", &file.field_descriptors),
        ] {
            assert!(
                descriptors.get().is_none(),
                "{} materialized all {kind} descriptors",
                file.entry_name
            );
        }
    }
    assert!(unsupported.is_empty(), "{}", unsupported.join("\n"));
}

#[test]
fn field_descriptor_lookups_do_not_materialize_descriptor_tables() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/alpha.dex");
    for sql in [
        "SELECT DISTINCT f.descriptor AS descriptor FROM fields f WHERE f.name = 'name' ORDER BY f.descriptor LIMIT 1",
        "SELECT DISTINCT c.descriptor AS descriptor FROM classes c JOIN class_fields cf ON cf.class_descriptor = c.descriptor WHERE cf.file_id = c.file_id AND cf.field_name = 'name' AND instr(cf.field_descriptor, ':Ljava/lang/String;') > 0 ORDER BY c.descriptor",
        "SELECT DISTINCT m.descriptor AS descriptor FROM methods m JOIN method_field_accesses fa ON fa.method = m.descriptor WHERE fa.file_id = m.file_id AND fa.method_idx = m.method_idx AND m.name = 'fieldTraffic' AND fa.field = 'Lfixtures/Alpha;->name:Ljava/lang/String;' AND fa.using_type = 'get' ORDER BY m.descriptor",
        "SELECT DISTINCT m.descriptor AS descriptor FROM methods m JOIN method_field_accesses fa ON fa.method = m.descriptor WHERE fa.file_id = m.file_id AND fa.method_idx = m.method_idx AND fa.field = 'Lfixtures/Alpha;->name:Ljava/lang/String;' AND fa.using_type = 'get' ORDER BY m.descriptor",
        "SELECT DISTINCT m.descriptor AS descriptor FROM methods m JOIN method_field_accesses fa ON fa.method = m.descriptor WHERE fa.file_id = m.file_id AND fa.method_idx = m.method_idx AND m.name = 'add' AND fa.field_name = 'name' AND fa.field_type = 'Ljava/lang/String;' AND fa.using_type = 'put' ORDER BY m.descriptor",
        "SELECT DISTINCT f.descriptor AS descriptor FROM fields f JOIN method_field_accesses fa ON fa.field = f.descriptor JOIN methods fm ON fm.descriptor = fa.method WHERE fa.file_id = f.file_id AND fa.field_idx = f.field_idx AND fm.file_id = fa.file_id AND fm.method_idx = fa.method_idx AND fa.using_type = 'get' AND fm.name = 'fieldTraffic' ORDER BY f.descriptor",
        "SELECT DISTINCT f.descriptor AS descriptor FROM fields f JOIN method_field_accesses fa ON fa.field = f.descriptor JOIN methods fm ON fm.descriptor = fa.method WHERE f.type_descriptor = 'Ljava/lang/String;' AND fa.file_id = f.file_id AND fa.field_idx = f.field_idx AND fm.file_id = fa.file_id AND fm.method_idx = fa.method_idx AND fa.using_type = 'get' AND fm.descriptor = 'Lfixtures/Alpha;->fieldTraffic()I' ORDER BY f.descriptor",
    ] {
        let dataset = Dataset::load_paths(std::slice::from_ref(&fixture)).unwrap();
        let query = parse(sql);
        let actual = fast_descriptor::try_fast_descriptor_lookup(&query, &dataset, None)
            .unwrap_or_else(|| panic!("field lookup must use the fast path: {sql}"))
            .unwrap();
        assert!(!actual.rows.is_empty(), "{sql}");
        for file in &dataset.files {
            assert!(file.field_descriptors.get().is_none(), "{sql}");
            assert!(file.method_descriptors.get().is_none(), "{sql}");
        }
        let expected = execute_query(&query, &dataset, Some(&dataset), &NamedCaches::default(), None, false).unwrap();
        assert_eq!(actual.columns, expected.columns, "{sql}");
        assert_eq!(actual.rows, expected.rows, "{sql}");
    }
}

#[test]
fn exact_method_descriptor_lookups_work_without_lookup_indexes() {
    let dataset = Dataset::load_paths_with_requirements(
        &[PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/alpha.dex")],
        IndexNeeds::default(),
        false,
        false,
        true,
    )
    .unwrap();
    assert!(dataset.files[0].methods_by_class.is_empty());
    for predicate in [
        "",
        " AND m.name = 'missing'",
        " AND m.descriptor = 'Lfixtures/Alpha;->helper()I'",
    ] {
        let query = parse(&format!("SELECT DISTINCT m.descriptor AS descriptor FROM methods m WHERE m.descriptor = 'Lfixtures/Alpha;->fieldTraffic()I'{predicate} ORDER BY m.descriptor"));
        let actual = fast_descriptor::try_fast_descriptor_lookup(&query, &dataset, None)
            .unwrap()
            .unwrap();
        assert_eq!(actual.rows.len(), usize::from(predicate.is_empty()));
        assert!(dataset.files[0].method_descriptors.get().is_none());
    }
}

#[test]
fn missing_field_access_descriptors_do_not_materialize_descriptor_tables() {
    let dataset = Dataset::load_paths(&[
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/alpha.dex")
    ])
    .unwrap();
    for descriptor in [
        "Lfixtures/Gamma;->name:Ljava/lang/String;",
        "Lfixtures/Alpha;->name:I",
        "not-a-field",
    ] {
        let query = parse(&format!("SELECT DISTINCT m.descriptor AS descriptor FROM methods m JOIN method_field_accesses fa ON fa.method = m.descriptor WHERE fa.file_id = m.file_id AND fa.method_idx = m.method_idx AND fa.field = '{descriptor}' ORDER BY m.descriptor"));
        let result = fast_descriptor::try_fast_descriptor_lookup(&query, &dataset, None)
            .unwrap()
            .unwrap();
        assert!(result.rows.is_empty(), "{descriptor}");
        assert!(dataset.files[0].field_descriptors.get().is_none());
        assert!(dataset.files[0].method_descriptors.get().is_none());
    }
}

#[test]
fn field_flag_lookup_requires_local_definition_identity() {
    let dataset = Dataset::load_paths(&[
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/alpha.dex")
    ])
    .unwrap();
    let sql = "SELECT DISTINCT f.descriptor AS descriptor FROM fields f JOIN class_fields cf ON cf.field_descriptor=f.descriptor WHERE f.class_descriptor='Lfixtures/Alpha;' AND (cf.access_flags & 1)=1 AND cf.file_id=f.file_id AND cf.field_idx=f.field_idx ORDER BY f.descriptor";
    let query = parse(sql);
    let actual = fast_descriptor::try_fast_descriptor_lookup(&query, &dataset, None)
        .unwrap()
        .unwrap();
    let expected = execute_query(
        &query,
        &dataset,
        Some(&dataset),
        &NamedCaches::default(),
        None,
        false,
    )
    .unwrap();
    assert_eq!(actual.rows, expected.rows);
    assert!(!actual.rows.is_empty());
    for identity in [" AND cf.file_id=f.file_id", " AND cf.field_idx=f.field_idx"] {
        assert!(fast_descriptor::try_fast_descriptor_lookup(
            &parse(&sql.replace(identity, "")),
            &dataset,
            None
        )
        .is_none());
    }
}

fn parse(sql: &str) -> sqlparser::ast::Query {
    let statements =
        sqlparser::parser::Parser::parse_sql(&sqlparser::dialect::SQLiteDialect {}, sql).unwrap();
    let sqlparser::ast::Statement::Query(query) = statements.into_iter().next().unwrap() else {
        panic!("expected query");
    };
    *query
}

fn select(query: &sqlparser::ast::Query) -> &sqlparser::ast::Select {
    query.body.as_select().unwrap()
}

#[test]
fn physical_scan_limit_preserves_offsets_and_aggregates() {
    let query = parse("SELECT descriptor FROM methods LIMIT 3 OFFSET 5");
    assert_eq!(query_scan_limit(select(&query), &query, None), Some(8));
    assert_eq!(query_scan_limit(select(&query), &query, Some(1)), Some(6));
    let query = parse("SELECT descriptor FROM methods LIMIT 5, 3");
    assert_eq!(query_scan_limit(select(&query), &query, None), Some(8));
    for sql in [
        "SELECT count(*) FROM methods LIMIT 1",
        "SELECT 1 + count(name) FROM methods LIMIT 1",
        "SELECT length(group_concat(name)) FROM methods LIMIT 1",
        "SELECT sum(method_idx) FROM methods LIMIT 1",
        "SELECT count(*) OVER () FROM methods LIMIT 1",
    ] {
        let query = parse(sql);
        assert_eq!(
            query_scan_limit(select(&query), &query, None),
            None,
            "{sql}"
        );
    }
}

#[test]
fn physical_scan_limit_requires_complete_predicate_pushdown() {
    for sql in [
        "SELECT descriptor FROM methods WHERE missing = 5 LIMIT 1",
        "SELECT descriptor FROM methods m WHERE other.method_idx = 5 LIMIT 1",
        "SELECT descriptor FROM methods WHERE method_idx + 1 = 5 LIMIT 1",
        "SELECT value FROM strings WHERE string_idx = 5 LIMIT 1",
    ] {
        let query = parse(sql);
        assert_eq!(
            query_scan_limit(select(&query), &query, None),
            None,
            "{sql}"
        );
    }
    for sql in [
        "SELECT descriptor FROM methods m WHERE m.method_idx = 5 LIMIT 1",
        "SELECT descriptor FROM classes WHERE class_idx = 5 LIMIT 1",
        "SELECT descriptor FROM fields WHERE field_idx = 5 LIMIT 1",
    ] {
        let query = parse(sql);
        assert_eq!(
            query_scan_limit(select(&query), &query, None),
            Some(1),
            "{sql}"
        );
    }
}

#[test]
fn pruning_keeps_group_having_and_order_dependencies() {
    let query = parse("SELECT class_descriptor, sum(method_idx) AS n FROM methods WHERE param_count = 1 GROUP BY class_descriptor HAVING sum(method_idx) > 1 ORDER BY name");
    let columns = query_scan_columns(select(&query), &query).unwrap();
    for required in ["class_descriptor", "method_idx", "param_count", "name"] {
        assert!(columns.contains(required), "missing {required}");
    }
    for sql in [
        "SELECT * FROM methods",
        "SELECT m.* FROM methods m",
        "SELECT count(*) FILTER (WHERE method_idx > 5) FROM methods",
        "SELECT sum(method_idx) OVER (ORDER BY name) FROM methods",
    ] {
        let query = parse(sql);
        assert!(
            query_scan_columns(select(&query), &query).is_none(),
            "{sql}"
        );
    }
}

#[test]
fn methods_topk_rejects_predicates_it_cannot_evaluate() {
    let ds = Dataset::default();
    for sql in [
        "SELECT descriptor FROM methods WHERE method_idx=5 ORDER BY descriptor LIMIT 1",
        "SELECT descriptor FROM methods WHERE file_id=0 ORDER BY descriptor LIMIT 1",
        "SELECT descriptor FROM methods WHERE param_count='1' ORDER BY descriptor LIMIT 1",
        "SELECT other.descriptor FROM methods ORDER BY descriptor LIMIT 1",
        "SELECT m.descriptor FROM methods m ORDER BY other.descriptor LIMIT 1",
    ] {
        assert!(fast_methods_topk(&parse(sql), &ds, None).is_none(), "{sql}");
    }
}

#[test]
fn topk_offset_and_generic_scanner_predicates_match_unbounded_results() {
    let ds = Dataset::load_paths(&[
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/alpha.dex")
    ])
    .unwrap();
    let caches = NamedCaches::default();
    for predicate in ["", " WHERE param_count=0"] {
        let all = fast_methods_topk(
            &parse(&format!(
                "SELECT descriptor FROM methods{predicate} ORDER BY descriptor LIMIT 100"
            )),
            &ds,
            None,
        )
        .unwrap()
        .unwrap();
        for cli_limit in [None, Some(1)] {
            let limited = fast_methods_topk(
                &parse(&format!("SELECT descriptor FROM methods{predicate} ORDER BY descriptor LIMIT 2 OFFSET 1")),
                &ds, cli_limit,
            ).unwrap().unwrap();
            assert_eq!(
                limited.rows,
                all.rows
                    .iter()
                    .skip(1)
                    .take(cli_limit.unwrap_or(2) as usize)
                    .cloned()
                    .collect::<Vec<_>>()
            );
        }
    }
    for (table, key) in [
        ("methods", "method_idx"),
        ("classes", "class_def_idx"),
        ("fields", "field_idx"),
    ] {
        let all = execute_query(
            &parse(&format!("SELECT {key} FROM {table}")),
            &ds,
            Some(&ds),
            &caches,
            None,
            false,
        )
        .unwrap();
        for row in &all.rows {
            let sql = format!("SELECT {key} FROM {table} WHERE {key}={} LIMIT 1", row[0]);
            let result = execute_query(&parse(&sql), &ds, Some(&ds), &caches, None, false).unwrap();
            assert_eq!(result.rows, vec![row.clone()], "{sql}");
        }
        let query = parse(&format!("SELECT {key} FROM {table} WHERE {key}=1 LIMIT 1"));
        let source = scan_factor(
            &select(&query).from[0].relation,
            &ds,
            Some(&[simple_push_predicate(select(&query).selection.as_ref().unwrap()).unwrap()]),
            None,
            false,
            &caches,
            Some(&ds),
            Some(1),
            None,
        )
        .unwrap();
        assert_eq!(source.len(), 1, "direct scanner {table}");
        assert_eq!(
            source[0].get(key),
            Some(&Scalar::Int(1)),
            "direct scanner {table}"
        );
    }
    let query = parse("SELECT count(name) FROM methods LIMIT 1");
    let result = execute_query(&query, &ds, Some(&ds), &caches, None, false).unwrap();
    assert_eq!(
        result.rows,
        vec![vec![ds.files[0].methods.len().to_string()]]
    );
}
