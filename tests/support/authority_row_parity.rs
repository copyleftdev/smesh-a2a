#![allow(dead_code, clippy::too_many_lines)]

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use rusqlite::{Connection, types::ValueRef};
use serde_json::{Map, Value};
use tokio_postgres::Client;

pub const AUTHORITY_TABLES: [&str; 17] = [
    "store_metadata",
    "store_identity",
    "tasks",
    "task_events",
    "idempotency_records",
    "outbox",
    "outbox_attempts",
    "receiver_inbox",
    "receiver_frames",
    "loopback_effects",
    "stream_transcripts",
    "stream_frames",
    "cancellation_intents",
    "authorization_decisions",
    "list_snapshots",
    "list_snapshot_entries",
    "list_page_tokens",
];

fn expected_tables() -> BTreeSet<String> {
    AUTHORITY_TABLES
        .iter()
        .map(|table| (*table).to_owned())
        .collect()
}

pub fn assert_sqlite_tables_match(path: &Path) {
    let connection = Connection::open(path).expect("open SQLite parity database");
    let mut statement = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .expect("prepare SQLite authority table inventory");
    let actual = statement
        .query_map([], |row| row.get::<_, String>(0))
        .expect("query SQLite authority table inventory")
        .collect::<Result<BTreeSet<_>, _>>()
        .expect("read SQLite authority table inventory");
    assert_eq!(
        actual,
        expected_tables(),
        "SQLite authority table set drifted"
    );
}

pub async fn assert_postgres_tables_match(client: &Client, schema: &str) {
    let mut actual = client
        .query(
            "SELECT table_name FROM information_schema.tables WHERE table_schema=$1 AND table_type='BASE TABLE' AND table_name<>'schema_migrations'",
            &[&schema],
        )
        .await
        .expect("query PostgreSQL authority table inventory")
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<BTreeSet<_>>();
    assert!(
        actual.remove("quota_reservations"),
        "PostgreSQL quota reservation seam table is missing"
    );
    assert_eq!(
        actual,
        expected_tables(),
        "PostgreSQL core authority table set drifted"
    );
    let columns = client
        .query(
            "SELECT column_name FROM information_schema.columns WHERE table_schema=$1 AND table_name='quota_reservations' ORDER BY ordinal_position",
            &[&schema],
        )
        .await
        .expect("query PostgreSQL quota seam columns")
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();
    assert_eq!(
        columns,
        [
            "tenant_scope",
            "reservation_id",
            "account_id",
            "principal_scope",
            "operation",
            "dimension",
            "units",
            "task_id",
            "expires_at",
            "metadata_json",
            "created_at",
        ]
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalAuthorityDump {
    pub rows: BTreeMap<String, Vec<Value>>,
    pub counts: BTreeMap<String, usize>,
}

impl LogicalAuthorityDump {
    fn new(mut rows: BTreeMap<String, Vec<Value>>) -> Self {
        normalize(&mut rows);
        let counts = rows
            .iter()
            .map(|(table, rows)| (table.clone(), rows.len()))
            .collect();
        Self { rows, counts }
    }
}

pub fn dump_sqlite(path: &Path) -> LogicalAuthorityDump {
    let connection = Connection::open(path).expect("open SQLite parity database");
    let mut tables = BTreeMap::new();
    for table in AUTHORITY_TABLES {
        let mut statement = connection
            .prepare(&format!("SELECT * FROM {table}"))
            .expect("prepare SQLite parity export");
        let names: Vec<String> = statement
            .column_names()
            .iter()
            .map(ToString::to_string)
            .collect();
        let rows = statement
            .query_map([], |row| {
                let mut object = Map::new();
                for (index, name) in names.iter().enumerate() {
                    let value = match row.get_ref(index)? {
                        ValueRef::Null => Value::Null,
                        ValueRef::Integer(value) => Value::from(value),
                        ValueRef::Real(value) => Value::from(value),
                        ValueRef::Text(value) => {
                            Value::String(String::from_utf8_lossy(value).into_owned())
                        }
                        ValueRef::Blob(value) => Value::String(hex(value)),
                    };
                    object.insert(name.clone(), value);
                }
                Ok(Value::Object(object))
            })
            .expect("query SQLite parity rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("read SQLite parity rows");
        tables.insert(table.to_owned(), rows);
    }
    LogicalAuthorityDump::new(tables)
}

pub async fn dump_postgres(client: &Client, schema: &str) -> LogicalAuthorityDump {
    let mut tables = BTreeMap::new();
    for table in AUTHORITY_TABLES {
        let sql = format!("SELECT row_to_json(t)::text FROM {schema}.{table} t");
        let rows = client
            .query(&sql, &[])
            .await
            .expect("query PostgreSQL parity rows")
            .into_iter()
            .map(|row| {
                serde_json::from_str::<Value>(row.get::<_, String>(0).as_str())
                    .expect("decode PostgreSQL parity row")
            })
            .collect();
        tables.insert(table.to_owned(), rows);
    }
    LogicalAuthorityDump::new(tables)
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("write to string");
    }
    encoded
}

fn normalize(tables: &mut BTreeMap<String, Vec<Value>>) {
    let decision_ranks: BTreeMap<String, i64> = {
        let mut decisions: Vec<(i64, String)> = tables
            .get("authorization_decisions")
            .into_iter()
            .flatten()
            .filter_map(|row| {
                Some((
                    row.get("decision_order")?.as_i64()?,
                    row.get("decision_id")?.as_str()?.to_owned(),
                ))
            })
            .collect();
        decisions.sort();
        decisions
            .into_iter()
            .enumerate()
            .map(|(rank, (_, id))| (id, i64::try_from(rank + 1).unwrap()))
            .collect()
    };
    let lease_aliases: BTreeMap<String, String> = tables
        .get("outbox_attempts")
        .into_iter()
        .flatten()
        .filter_map(|row| {
            Some((
                row.get("lease_token")?.as_str()?.to_owned(),
                format!("lease:{}:{}", row.get("outbox_id")?, row.get("attempt_no")?),
            ))
        })
        .collect();
    let sender_by_dispatch: BTreeMap<String, (i64, String)> = tables
        .get("outbox")
        .into_iter()
        .flatten()
        .filter_map(|outbox| {
            let dispatch = outbox.get("dispatch_id")?.as_str()?.to_owned();
            let outbox_id = outbox.get("outbox_id")?.as_i64()?;
            let attempt_no = outbox.get("attempt_count")?.as_i64()?;
            let token = tables
                .get("outbox_attempts")?
                .iter()
                .find(|attempt| {
                    attempt.get("outbox_id").and_then(Value::as_i64) == Some(outbox_id)
                        && attempt.get("attempt_no").and_then(Value::as_i64) == Some(attempt_no)
                })?
                .get("lease_token")?
                .as_str()?
                .to_owned();
            Some((dispatch, (attempt_no, token)))
        })
        .collect();
    let snapshots: BTreeMap<String, String> = tables
        .get("list_snapshots")
        .into_iter()
        .flatten()
        .filter_map(|row| {
            let raw = row.get("snapshot_id")?.as_str()?.to_owned();
            let mut semantic = row.clone();
            let object = semantic.as_object_mut()?;
            object.remove("snapshot_id");
            object.remove("tenant_scope");
            object.remove("owner_account_id");
            object.remove("metadata_digest");
            let issued = object.remove("issued_at")?.as_i64()?;
            let expires = object.remove("expires_at")?.as_i64()?;
            object.insert("ttl_millis".into(), Value::from(expires - issued));
            let mut entries = tables
                .get("list_snapshot_entries")?
                .iter()
                .filter(|entry| {
                    entry.get("snapshot_id").and_then(Value::as_str) == Some(raw.as_str())
                })
                .cloned()
                .collect::<Vec<_>>();
            for entry in &mut entries {
                if let Some(entry) = entry.as_object_mut() {
                    entry.remove("snapshot_id");
                    entry.remove("tenant_scope");
                }
            }
            entries.sort_by_key(Value::to_string);
            object.insert("ordered_entries".into(), Value::Array(entries));
            Some((
                raw,
                format!(
                    "snapshot:{}",
                    smesh_a2a::content_digest(semantic.to_string().as_bytes())
                ),
            ))
        })
        .collect();

    for (table, rows) in tables.iter_mut() {
        for row in rows.iter_mut() {
            let Some(object) = row.as_object_mut() else {
                continue;
            };
            if table == "receiver_inbox"
                && !object.contains_key("sender_attempt_no")
                && let Some(dispatch) = object.get("dispatch_id").and_then(Value::as_str)
                && let Some((attempt, token)) = sender_by_dispatch.get(dispatch)
            {
                object.insert("sender_attempt_no".into(), Value::from(*attempt));
                object.insert("sender_lease_token".into(), Value::String(token.clone()));
            }
            if let Some(Value::String(value)) = object.get_mut("snapshot_id")
                && let Some(alias) = snapshots.get(value)
            {
                *value = alias.clone();
            }
            if let Some(Value::String(value)) = object.get_mut("lease_token")
                && let Some(alias) = lease_aliases.get(value)
            {
                *value = alias.clone();
            }
            if let Some(Value::String(value)) = object.get_mut("sender_lease_token")
                && let Some(alias) = lease_aliases.get(value)
            {
                *value = alias.clone();
            }
            if object
                .get("token_hash")
                .is_some_and(|value| !value.is_null())
            {
                let alias = format!(
                    "page-token:{}:{}:{}:{}",
                    object
                        .get("snapshot_id")
                        .and_then(Value::as_str)
                        .unwrap_or("missing"),
                    object.get("next_position").unwrap_or(&Value::Null),
                    object.get("token_version").unwrap_or(&Value::Null),
                    object.get("key_generation").unwrap_or(&Value::Null),
                );
                object.insert("token_hash".into(), Value::String(alias));
            }
            if object
                .get("metadata_digest")
                .is_some_and(|value| !value.is_null())
            {
                let alias = format!(
                    "snapshot-metadata:{}",
                    object
                        .get("snapshot_id")
                        .and_then(Value::as_str)
                        .unwrap_or("missing")
                );
                object.insert("metadata_digest".into(), Value::String(alias));
            }
            match table.as_str() {
                "store_metadata" => {
                    for field in ["cursor_key", "receipt_key"] {
                        if let Some(value) = object.get_mut(field) {
                            let encoded_len = value.as_str().map_or(0, str::len);
                            let bytes = if encoded_len == 66 {
                                32
                            } else {
                                encoded_len / 2
                            };
                            *value = Value::String(format!("hmac-key-generation-1:{bytes}-bytes"));
                        }
                    }
                    for field in ["migration_hash", "catalog_hash"] {
                        if let Some(value) = object.get_mut(field) {
                            *value = Value::String(format!(
                                "sealed-sha256:{}-chars",
                                value.as_str().map_or(0, str::len)
                            ));
                        }
                    }
                    object.remove("catalog_hash");
                }
                "store_identity" => {
                    // SQLite persists the development tenant/policy binding while PostgreSQL
                    // persists a random store id. Both are backend identity anchors; secrets and
                    // backend-specific identity representation are intentionally not compared.
                    object.clear();
                    object.insert(
                        "identity_persisted".into(),
                        Value::String("immutable-authority-anchor".into()),
                    );
                    object.insert(
                        "creation_semantics".into(),
                        Value::String("created-once-during-migration".into()),
                    );
                }
                "outbox_attempts" => {
                    // SQLite's parent outbox id is globally unique; PostgreSQL repeats the tenant
                    // in the composite foreign key. The tenant is already compared on outbox.
                    object.remove("tenant_scope");
                }
                "authorization_decisions" => {
                    if let Some(id) = object.get("decision_id").and_then(Value::as_str)
                        && let Some(rank) = decision_ranks.get(id)
                    {
                        object.insert("decision_order".into(), Value::from(*rank));
                    }
                }
                "list_snapshots" | "list_page_tokens" => {
                    // SQLite snapshots live in the single database tenant selected by their
                    // frozen rows; PostgreSQL repeats tenant ownership for RLS/composite FKs.
                    object.remove("tenant_scope");
                    if table == "list_snapshots" {
                        object.remove("owner_account_id");
                    }
                    let issued = object.get("issued_at").and_then(Value::as_i64);
                    let expires = object.get("expires_at").and_then(Value::as_i64);
                    if let (Some(issued), Some(expires)) = (issued, expires) {
                        object.insert("ttl_millis".into(), Value::from(expires - issued));
                        object.insert("issued_at".into(), Value::String("db-time".into()));
                        object.insert("expires_at".into(), Value::String("db-time+ttl".into()));
                    }
                }
                "list_snapshot_entries" => {
                    object.remove("tenant_scope");
                }
                _ => {}
            }
        }
        rows.sort_by_key(Value::to_string);
    }
}
