CREATE DATABASE IF NOT EXISTS sts;
CREATE TABLE IF NOT EXISTS sts.events (event_id String, tenant String, user String, device String, site String, ts DateTime64(3), source String, app String, category String, bytes_in UInt64, bytes_out UInt64, verdict String, geo String, query String, entropy Float64, attack_type String)
ENGINE = MergeTree PARTITION BY (tenant, toYYYYMM(ts)) ORDER BY (tenant, user, ts);
CREATE TABLE IF NOT EXISTS sts.incidents (user String, tenant String, ts DateTime64(3), confidence Float64, summary String)
ENGINE = MergeTree PARTITION BY tenant ORDER BY (tenant, ts);
