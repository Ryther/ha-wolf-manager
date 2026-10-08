//! Bounded operation history; retention never removes uncertain work or PC data.
use crate::{
    domain::{ensure_pc, time},
    protected::internal,
    store::{Store, decode},
};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;
use wolf_core::*;
#[derive(Debug, Clone, serde::Serialize)]
pub struct Operation {
    pub operation_id: Uuid,
    pub pc_id: PcId,
    pub kind: OperationKind,
    pub state: OperationState,
    pub desired_revision: Option<Revision>,
    pub submitted_at: i64,
    pub started_at: Option<i64>,
    pub completed_at: Option<i64>,
    pub sanitized_result: Option<serde_json::Value>,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationCursor {
    pub submitted_at: i64,
    pub operation_id: Uuid,
}
impl OperationCursor {
    pub fn encode(&self) -> String {
        format!("{}:{}", self.submitted_at, self.operation_id)
    }
    pub fn parse(value: &str) -> Result<Self, SafeError> {
        if value.len() > 80 {
            return Err(SafeError::validation());
        }
        let (time, id) = value.split_once(':').ok_or_else(SafeError::validation)?;
        let submitted_at = time.parse::<i64>().map_err(|_| SafeError::validation())?;
        let operation_id = Uuid::parse_str(id).map_err(|_| SafeError::validation())?;
        if submitted_at < 0 || operation_id.is_nil() || operation_id.to_string() != id {
            return Err(SafeError::validation());
        }
        Ok(Self {
            submitted_at,
            operation_id,
        })
    }
}
#[derive(serde::Serialize)]
pub struct OperationPage {
    pub operations: Vec<Operation>,
    pub next_cursor: Option<String>,
}
struct RawOperation {
    id: String,
    pc: String,
    kind: String,
    state: String,
    revision: Option<Vec<u8>>,
    submitted: i64,
    started: Option<i64>,
    completed: Option<i64>,
    result: Option<String>,
}
impl RawOperation {
    fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            pc: r.get(1)?,
            kind: r.get(2)?,
            state: r.get(3)?,
            revision: r.get(4)?,
            submitted: r.get(5)?,
            started: r.get(6)?,
            completed: r.get(7)?,
            result: r.get(8)?,
        })
    }
    fn validated(self) -> Result<Operation, SafeError> {
        if self.result.as_ref().is_some_and(|s| s.len() > 65536) {
            return Err(SafeError::new("payload_too_large"));
        }
        Ok(Operation {
            operation_id: Uuid::parse_str(&self.id).map_err(internal)?,
            pc_id: PcId::new(self.pc)?,
            kind: serde_json::from_value(serde_json::Value::String(self.kind)).map_err(internal)?,
            state: serde_json::from_value(serde_json::Value::String(self.state))
                .map_err(internal)?,
            desired_revision: self
                .revision
                .map(|v| Revision::new(v.iter().map(|b| format!("{b:02x}")).collect::<String>()))
                .transpose()?,
            submitted_at: self.submitted,
            started_at: self.started,
            completed_at: self.completed,
            sanitized_result: self.result.as_ref().map(|v| decode(v)).transpose()?,
        })
    }
}
const COLUMNS: &str = "operation_id,pc_id,kind,state,desired_revision,submitted_at_ms,started_at_ms,completed_at_ms,sanitized_result";
impl Store {
    pub fn operation(&self, id: Uuid) -> Result<Operation, SafeError> {
        self.root.verify()?;
        self.conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM operations WHERE operation_id=?1"),
                [id.to_string()],
                RawOperation::row,
            )
            .optional()
            .map_err(internal)?
            .ok_or_else(|| SafeError::new("not_found"))?
            .validated()
    }
    pub fn operation_page(
        &self,
        pc: &PcId,
        limit: u16,
        cursor: Option<&OperationCursor>,
    ) -> Result<OperationPage, SafeError> {
        self.root.verify()?;
        ensure_pc(&self.conn, pc)?;
        if !(1..=100).contains(&limit)
            || cursor.is_some_and(|c| c.submitted_at < 0 || c.operation_id.is_nil())
        {
            return Err(SafeError::validation());
        }
        let sql = format!(
            "SELECT {COLUMNS} FROM operations WHERE pc_id=?1 AND (?2 IS NULL OR submitted_at_ms<?2 OR (submitted_at_ms=?2 AND operation_id<?3)) ORDER BY submitted_at_ms DESC,operation_id DESC LIMIT ?4"
        );
        let mut operations = self
            .conn
            .prepare(&sql)
            .map_err(internal)?
            .query_map(
                params![
                    pc.as_str(),
                    cursor.map(|c| c.submitted_at),
                    cursor.map(|c| c.operation_id.to_string()),
                    i64::from(limit) + 1
                ],
                RawOperation::row,
            )
            .map_err(internal)?
            .map(|row| row.map_err(internal)?.validated())
            .collect::<Result<Vec<_>, _>>()?;
        let more = operations.len() > usize::from(limit);
        operations.truncate(usize::from(limit));
        let next_cursor = if more {
            operations.last().map(|o| {
                OperationCursor {
                    submitted_at: o.submitted_at,
                    operation_id: o.operation_id,
                }
                .encode()
            })
        } else {
            None
        };
        Ok(OperationPage {
            operations,
            next_cursor,
        })
    }
    pub fn prune_terminal_operations(&mut self, now: i64) -> Result<usize, SafeError> {
        self.root.verify()?;
        time(now)?;
        const SELECTION: &str = "SELECT operation_id FROM (SELECT operation_id,COALESCE(completed_at_ms,submitted_at_ms) AS terminal_at,ROW_NUMBER() OVER(PARTITION BY pc_id ORDER BY COALESCE(completed_at_ms,submitted_at_ms) DESC,operation_id DESC) AS position FROM operations WHERE state IN ('succeeded','failed','rejected')) WHERE terminal_at<?1 OR position>1000";
        let cutoff = now - 30 * 24 * 60 * 60 * 1000;
        let tx = self.conn.transaction().map_err(internal)?;
        tx.execute(
            &format!("DELETE FROM operation_rpc_requests WHERE operation_id IN ({SELECTION})"),
            [cutoff],
        )
        .map_err(internal)?;
        let deleted = tx
            .execute(
                &format!("DELETE FROM operations WHERE operation_id IN ({SELECTION})"),
                [cutoff],
            )
            .map_err(internal)?;
        tx.commit().map_err(internal)?;
        Ok(deleted)
    }
}
