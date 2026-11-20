-- DuckDB local fallback: `duckdb -c ".read store/duckdb.sql"` after the pipeline writes data/events.jsonl
CREATE OR REPLACE VIEW events AS SELECT * FROM read_json_auto('data/events.jsonl');
-- example: SELECT tenant, user, sum(bytes_out) b FROM events GROUP BY ALL ORDER BY b DESC LIMIT 20;
