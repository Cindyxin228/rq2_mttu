use std::{env, time::Duration};

use anyhow::Result;
use chrono::{DateTime, Utc};
use dotenvy::dotenv;
use sqlx::{PgPool, Row, postgres::PgPoolOptions};

pub struct Database {
    pool: PgPool,
}

#[derive(Clone)]
pub struct DownstreamVersionInfo {
    pub crate_name: String,
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub dep_req: String,
}

impl Database {
    pub async fn connect_from_env() -> Result<Self> {
        dotenv().ok();

        let host = env::var("PG_HOST").unwrap_or_else(|_| "localhost:5432".to_string());
        let user = env::var("PG_USER").unwrap_or_else(|_| "postgres".to_string());
        let password = env::var("PG_PASSWORD").unwrap_or_else(|_| "".to_string());
        let database = env::var("PG_DATABASE").unwrap_or_else(|_| "crates_io".to_string());

        let pool_max: u32 = env::var("PG_POOL_MAX")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);
        let pool_timeout_ms: u64 = env::var("PG_POOL_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3000);

        let url = format!("postgres://{user}:{password}@{host}/{database}");

        let pool = PgPoolOptions::new()
            .max_connections(pool_max)
            .acquire_timeout(Duration::from_millis(pool_timeout_ms))
            .connect(&url)
            .await?;

        Ok(Self { pool })
    }

    pub async fn query_all_downstream_details(
        &self,
        target_crate: &str,
    ) -> Result<Vec<DownstreamVersionInfo>> {
        let rows = sqlx::query(
            r#"
            SELECT
                downstream_crates.name AS crate_name,
                downstream_versions.num AS version,
                downstream_versions.created_at AS created_at,
                dependencies.req AS dep_req
            FROM dependencies
            JOIN versions AS downstream_versions
                ON dependencies.version_id = downstream_versions.id
            JOIN crates AS downstream_crates
                ON downstream_versions.crate_id = downstream_crates.id
            WHERE
                dependencies.crate_id = (
                    SELECT id FROM crates WHERE name = $1
                )
                AND dependencies.kind = 0
            ORDER BY downstream_crates.name ASC, downstream_versions.created_at ASC, downstream_versions.num ASC
            "#,
        )
        .bind(target_crate)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(DownstreamVersionInfo {
                crate_name: row.try_get("crate_name")?,
                version: row.try_get("version")?,
                created_at: row.try_get("created_at")?,
                dep_req: row.try_get("dep_req")?,
            });
        }

        Ok(out)
    }

    pub async fn query_version_time(
        &self,
        crate_name: &str,
        version: &str,
    ) -> Result<Option<DateTime<Utc>>> {
        let row = sqlx::query(
            r#"
            SELECT v.created_at AS created_at
            FROM versions v
            JOIN crates c
                ON v.crate_id = c.id
            WHERE c.name = $1
              AND v.num = $2
            LIMIT 1
            "#,
        )
        .bind(crate_name)
        .bind(version)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.try_get("created_at")).transpose()?)
    }

    pub async fn query_all_version_numbers(&self, crate_name: &str) -> Result<Vec<String>> {
        let rows = sqlx::query(
            r#"
            SELECT v.num AS num
            FROM versions v
            JOIN crates c
                ON v.crate_id = c.id
            WHERE c.name = $1
            "#,
        )
        .bind(crate_name)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(row.try_get("num")?);
        }
        Ok(out)
    }
}
