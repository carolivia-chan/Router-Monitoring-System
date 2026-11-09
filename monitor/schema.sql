-- NetMon schema (PostgreSQL >= 12). Star schema:
--   dimension tables: source, target, asn       -> 1 row per entity, natural key
--   fact tables:      probe_result, trace_run, trace_hop, alert_event, probe_hourly
-- storage.py runs this file ONE STATEMENT AT A TIME on every connection, and Docker runs it when creating a new DB,
-- so every statement must be safe to run many times (IF NOT EXISTS / ON CONFLICT / checked first).

-- Fields of 1 measurement source (see v_source / v_probe at the end of the file):
--   source_type      Local | Globalping                   = source.kind
--   source_key       laptop/vnpt | gp/JP/Tokyo            = source.name (key)
--   source_location  - | Tokyo, Japan                     = source.location (Globalping only)
--   source_asn       AS45899 | AS2516                     = probe_result.source_asn / trace_run.source_asn (PER
--                                                           MEASUREMENT: Globalping may pick a probe on another network in the same city)
--   display_name     Laptop · VNPT · mon1 | Tokyo, Japan  = netmon_display(source, iface)

-- ================================================================ dimension tables
CREATE TABLE IF NOT EXISTS source (                 -- measurement source (where the measurement machine / probe is)
    name          TEXT PRIMARY KEY,                 -- source_key: laptop/vnpt (machine/ISP) | gp/JP/Tokyo (Globalping)
    kind          TEXT GENERATED ALWAYS AS (CASE WHEN name LIKE 'gp/%' THEN 'globalping' ELSE 'local' END) STORED,
    machine       TEXT GENERATED ALWAYS AS (CASE WHEN name LIKE 'gp/%' THEN NULL
                                                 ELSE split_part(name, '/', 1) END) STORED,
    isp           TEXT GENERATED ALWAYS AS (CASE WHEN name LIKE 'gp/%' THEN NULL       -- local machines only: from MaxMind
                                                 ELSE NULLIF(split_part(name, '/', 2), '') END) STORED,
    probe_country TEXT GENERATED ALWAYS AS (CASE WHEN name LIKE 'gp/%'                 -- Globalping only: where the probe is,
                                                 THEN NULLIF(split_part(name, '/', 2), '') END) STORED,  -- NOT the ISP
    probe_city    TEXT GENERATED ALWAYS AS (CASE WHEN name LIKE 'gp/%'
                                                 THEN NULLIF(split_part(name, '/', 3), '') END) STORED,
    location      TEXT,                             -- source_location: 'Tokyo, Japan' (Globalping only, written by NetMon)
    display       TEXT,                             -- 'Laptop · VNPT' | 'Tokyo, Japan' (written by NetMon)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- upgrade an old source table (machine/uplink split from the key, gp/JP misread as uplink = 'JP'): rebuild the generated columns
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'source' AND column_name = 'isp') THEN
        ALTER TABLE source DROP COLUMN IF EXISTS uplink;
        ALTER TABLE source DROP COLUMN IF EXISTS machine;
        ALTER TABLE source ADD COLUMN machine TEXT GENERATED ALWAYS AS
            (CASE WHEN name LIKE 'gp/%' THEN NULL ELSE split_part(name, '/', 1) END) STORED;
        ALTER TABLE source ADD COLUMN isp TEXT GENERATED ALWAYS AS
            (CASE WHEN name LIKE 'gp/%' THEN NULL ELSE NULLIF(split_part(name, '/', 2), '') END) STORED;
        ALTER TABLE source ADD COLUMN probe_country TEXT GENERATED ALWAYS AS
            (CASE WHEN name LIKE 'gp/%' THEN NULLIF(split_part(name, '/', 2), '') END) STORED;
        ALTER TABLE source ADD COLUMN probe_city TEXT GENERATED ALWAYS AS
            (CASE WHEN name LIKE 'gp/%' THEN NULLIF(split_part(name, '/', 3), '') END) STORED;
    END IF;
END $$;
ALTER TABLE source ADD COLUMN IF NOT EXISTS display TEXT;
ALTER TABLE source ADD COLUMN IF NOT EXISTS location TEXT;
-- old name 'Globalping · Tokyo, Japan' -> emptied, NetMon fills in 'Tokyo, Japan' again (the word Globalping is the source_type)
UPDATE source SET display = NULL WHERE display LIKE 'Globalping · %';

CREATE TABLE IF NOT EXISTS target (                 -- target server (from targets.csv)
    ip         TEXT PRIMARY KEY,
    name       TEXT,
    country    TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS asn (                    -- autonomous system (network operator) seen along the path
    asn        TEXT PRIMARY KEY,                    -- e.g. 'AS7552'
    org        TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ================================================================ fact tables
CREATE TABLE IF NOT EXISTS probe_result (           -- 1 row = 1 measurement of 1 server from 1 measurement point
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL,
    source      TEXT,
    source_asn  TEXT,                               -- ASN of the measurement point network at measurement time (AS45899, AS2516)
    iface       TEXT,                               -- sub-interface monN; Globalping probes have none -> NULL
    target_name TEXT,                               -- name at measurement time (keeps history when a server is renamed)
    target_ip   TEXT NOT NULL,
    country     TEXT,
    avg_ms      DOUBLE PRECISION,
    median_ms   DOUBLE PRECISION,
    jitter_ms   DOUBLE PRECISION,
    loss_pct    DOUBLE PRECISION,
    status      TEXT NOT NULL,
    health         TEXT,                            -- HEALTHY | DEGRADED | UNSTABLE | DOWN | UNKNOWN (monitor/health.py)
    base_median_ms DOUBLE PRECISION,                -- baseline used to assess this round (NULL = still learning)
    base_jitter_ms DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_probe_ts  ON probe_result (ts DESC);
CREATE INDEX IF NOT EXISTS idx_probe_key ON probe_result (iface, target_ip, ts DESC);

CREATE TABLE IF NOT EXISTS trace_run (              -- 1 row = 1 mtr/traceroute run
    id             BIGSERIAL PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL,
    source         TEXT,
    source_asn     TEXT,
    iface          TEXT,
    target_ip      TEXT NOT NULL,
    hop_count      INT,
    reached        BOOLEAN,
    asn_path       TEXT,
    country_path   TEXT,
    bottleneck_hop INT,
    bottleneck_ms  DOUBLE PRECISION,
    tool           TEXT,
    dest_loss_pct  DOUBLE PRECISION,
    loss_start_hop INT,
    loss_where     TEXT,
    loss_text      TEXT
);
CREATE INDEX IF NOT EXISTS idx_trace_key ON trace_run (iface, target_ip, ts DESC);

CREATE TABLE IF NOT EXISTS trace_hop (              -- 1 row = 1 hop of 1 trace
    run_id   BIGINT NOT NULL REFERENCES trace_run(id) ON DELETE CASCADE,
    hop      INT NOT NULL,
    ip       TEXT,
    country  TEXT,
    asn      TEXT,
    org      TEXT,
    loss_pct  DOUBLE PRECISION,
    avg_ms    DOUBLE PRECISION,
    median_ms DOUBLE PRECISION,
    best_ms   DOUBLE PRECISION,
    worst_ms  DOUBLE PRECISION,
    PRIMARY KEY (run_id, hop)
);

-- upgrade a DB created by an earlier version
ALTER TABLE probe_result ADD COLUMN IF NOT EXISTS median_ms DOUBLE PRECISION;
ALTER TABLE trace_run    ADD COLUMN IF NOT EXISTS tool TEXT;
ALTER TABLE trace_hop    ADD COLUMN IF NOT EXISTS median_ms DOUBLE PRECISION;
ALTER TABLE trace_hop    ADD COLUMN IF NOT EXISTS best_ms DOUBLE PRECISION;
ALTER TABLE trace_hop    ADD COLUMN IF NOT EXISTS worst_ms DOUBLE PRECISION;
ALTER TABLE trace_run    ADD COLUMN IF NOT EXISTS dest_loss_pct DOUBLE PRECISION;
ALTER TABLE trace_run    ADD COLUMN IF NOT EXISTS loss_start_hop INT;
ALTER TABLE trace_run    ADD COLUMN IF NOT EXISTS loss_where TEXT;
ALTER TABLE trace_run    ADD COLUMN IF NOT EXISTS loss_text TEXT;
ALTER TABLE probe_result ADD COLUMN IF NOT EXISTS source TEXT;
ALTER TABLE trace_run    ADD COLUMN IF NOT EXISTS source TEXT;
ALTER TABLE probe_result ADD COLUMN IF NOT EXISTS health TEXT;
ALTER TABLE probe_result ADD COLUMN IF NOT EXISTS base_median_ms DOUBLE PRECISION;
ALTER TABLE probe_result ADD COLUMN IF NOT EXISTS base_jitter_ms DOUBLE PRECISION;
CREATE INDEX IF NOT EXISTS idx_probe_src ON probe_result (source, ts DESC);
CREATE INDEX IF NOT EXISTS idx_trace_src ON trace_run (source, iface, target_ip, ts);

-- foreign keys fact -> dimension. Runs ONCE when upgrading an old DB: fill the dimension tables from the existing data
-- first, then add the constraints (old data must satisfy them). Later the constraints exist -> the whole block is skipped.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_probe_target') THEN
        INSERT INTO target (ip, name, country)
            SELECT DISTINCT ON (target_ip) target_ip, target_name, country
            FROM probe_result ORDER BY target_ip, ts DESC
        ON CONFLICT (ip) DO NOTHING;
        INSERT INTO target (ip) SELECT DISTINCT target_ip FROM trace_run ON CONFLICT (ip) DO NOTHING;
        INSERT INTO source (name)
            SELECT source FROM probe_result WHERE source IS NOT NULL
            UNION SELECT source FROM trace_run WHERE source IS NOT NULL
        ON CONFLICT (name) DO NOTHING;
        INSERT INTO asn (asn, org)
            SELECT DISTINCT ON (asn) asn, org FROM trace_hop WHERE asn IS NOT NULL ORDER BY asn
        ON CONFLICT (asn) DO NOTHING;
        ALTER TABLE probe_result ADD CONSTRAINT fk_probe_target
            FOREIGN KEY (target_ip) REFERENCES target(ip) ON UPDATE CASCADE;
        ALTER TABLE probe_result ADD CONSTRAINT fk_probe_source
            FOREIGN KEY (source) REFERENCES source(name) ON UPDATE CASCADE;
        ALTER TABLE trace_run ADD CONSTRAINT fk_trace_target
            FOREIGN KEY (target_ip) REFERENCES target(ip) ON UPDATE CASCADE;
        ALTER TABLE trace_run ADD CONSTRAINT fk_trace_source
            FOREIGN KEY (source) REFERENCES source(name) ON UPDATE CASCADE;
        ALTER TABLE trace_hop ADD CONSTRAINT fk_hop_asn
            FOREIGN KEY (asn) REFERENCES asn(asn) ON UPDATE CASCADE;
    END IF;
END $$;

-- ================================================================ analysis tables
CREATE TABLE IF NOT EXISTS alert_event (            -- every Telegram message sent (even when Telegram is not configured)
    id        BIGSERIAL PRIMARY KEY,
    ts        TIMESTAMPTZ NOT NULL DEFAULT now(),
    source    TEXT REFERENCES source(name) ON UPDATE CASCADE,
    iface     TEXT,
    target_ip TEXT REFERENCES target(ip) ON UPDATE CASCADE,
    kind      TEXT NOT NULL,                        -- health | path | route | no-subif (old versions: down, loss, lat, jit...)
    state     TEXT NOT NULL CHECK (state IN ('alert', 'recover', 'event')),
    message   TEXT,
    status    TEXT,                                 -- DEGRADED | UNSTABLE | DOWN | PATH | HEALTHY (recovery message)
    severity  TEXT                                  -- WARNING | CRITICAL
);
ALTER TABLE alert_event ADD COLUMN IF NOT EXISTS status TEXT;
ALTER TABLE alert_event ADD COLUMN IF NOT EXISTS severity TEXT;
CREATE INDEX IF NOT EXISTS idx_alert_ts  ON alert_event (ts DESC);
CREATE INDEX IF NOT EXISTS idx_alert_key ON alert_event (source, iface, target_ip, kind, ts);

CREATE TABLE IF NOT EXISTS probe_hourly (           -- hourly aggregates of probe_result (storage.rollup)
    hour          TIMESTAMPTZ NOT NULL,             -- start of the hour (date_trunc('hour', ts))
    source        TEXT NOT NULL REFERENCES source(name) ON UPDATE CASCADE,
    iface         TEXT NOT NULL DEFAULT '',         -- '' = Globalping probe (no sub-interface)
    target_ip     TEXT NOT NULL REFERENCES target(ip) ON UPDATE CASCADE,
    source_asn    TEXT NOT NULL DEFAULT '',         -- 2 different networks in the same city are not merged
    samples       INT NOT NULL,                     -- measurements in the hour
    up_samples    INT NOT NULL,                     -- UP measurements -> availability = up_samples / samples
    median_ms     DOUBLE PRECISION,                 -- median of the per-measurement medians
    p95_ms        DOUBLE PRECISION,                 -- 95th percentile of the per-measurement medians
    avg_jitter_ms DOUBLE PRECISION,
    avg_loss_pct  DOUBLE PRECISION,
    PRIMARY KEY (hour, source, iface, target_ip, source_asn)
);
CREATE INDEX IF NOT EXISTS idx_hourly_key ON probe_hourly (source, target_ip, hour DESC);

-- one-time upgrade: Globalping probes have no sub-interface -> iface NULL, the probe ASN (formerly written into iface)
-- moves to source_asn; local machines: source_asn = ISP ASN (MaxMind, first public hop, most frequent value
-- per measurement source)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'probe_result' AND column_name = 'source_asn') THEN
        ALTER TABLE probe_result ALTER COLUMN iface DROP NOT NULL;
        ALTER TABLE trace_run    ALTER COLUMN iface DROP NOT NULL;
        ALTER TABLE probe_result ADD COLUMN source_asn TEXT;
        ALTER TABLE trace_run    ADD COLUMN source_asn TEXT;
        UPDATE probe_result SET source_asn = iface, iface = NULL WHERE source LIKE 'gp/%' AND iface LIKE 'AS%';
        UPDATE trace_run    SET source_asn = iface, iface = NULL WHERE source LIKE 'gp/%' AND iface LIKE 'AS%';
        CREATE TEMP TABLE _isp_asn ON COMMIT DROP AS
        SELECT DISTINCT ON (source) source, asn FROM (
            SELECT r.source, x.asn, count(*) AS n
            FROM trace_run r
            CROSS JOIN LATERAL (SELECT h.asn FROM trace_hop h
                                WHERE h.run_id = r.id AND h.asn IS NOT NULL AND h.ip IS DISTINCT FROM r.target_ip
                                ORDER BY h.hop LIMIT 1) x
            WHERE r.source IS NOT NULL AND r.source NOT LIKE 'gp/%'
            GROUP BY 1, 2) v
        ORDER BY source, n DESC;
        UPDATE probe_result p SET source_asn = a.asn FROM _isp_asn a WHERE p.source = a.source AND p.source_asn IS NULL;
        UPDATE trace_run r SET source_asn = a.asn FROM _isp_asn a WHERE r.source = a.source AND r.source_asn IS NULL;
    END IF;
END $$;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'probe_hourly' AND column_name = 'source_asn') THEN
        ALTER TABLE probe_hourly DROP CONSTRAINT probe_hourly_pkey;
        ALTER TABLE probe_hourly ADD COLUMN source_asn TEXT NOT NULL DEFAULT '';
        ALTER TABLE probe_hourly ALTER COLUMN iface SET DEFAULT '';
        UPDATE probe_hourly SET source_asn = iface, iface = '' WHERE source LIKE 'gp/%' AND iface LIKE 'AS%';
        UPDATE probe_hourly h SET source_asn = a.source_asn
        FROM (SELECT DISTINCT ON (source) source, source_asn FROM (
                  SELECT source, source_asn, count(*) AS n FROM probe_result
                  WHERE source NOT LIKE 'gp/%' AND source_asn IS NOT NULL GROUP BY 1, 2) v
              ORDER BY source, n DESC) a
        WHERE h.source = a.source AND h.source_asn = '';
        ALTER TABLE probe_hourly ADD PRIMARY KEY (hour, source, iface, target_ip, source_asn);
    END IF;
END $$;

-- latest state of each (source, monN, server) pair in the last hour
CREATE OR REPLACE VIEW v_latest_status AS
SELECT DISTINCT ON (p.source, p.iface, p.target_ip)
       p.source, p.iface, p.target_ip, t.name AS target_name, t.country,
       p.ts, p.status, p.median_ms, p.jitter_ms, p.loss_pct, p.source_asn
FROM probe_result p
JOIN target t ON t.ip = p.target_ip
WHERE p.ts > now() - interval '1 hour'
ORDER BY p.source, p.iface, p.target_ip, p.ts DESC;

-- every time the AS path differs from the previous trace (that reached the destination) of the same measurement
-- point: a BGP-level change. Measurement point = (source, iface, source_asn): Globalping probes on different
-- networks in the same city taking different paths is normal and not counted as a route change.
CREATE OR REPLACE VIEW v_route_change AS
SELECT ts, source, iface, target_ip,
       prev_asn_path AS old_asn_path, asn_path AS new_asn_path,
       prev_country_path AS old_country_path, country_path AS new_country_path,
       prev_hops AS old_hops, hop_count AS new_hops, source_asn
FROM (
    SELECT ts, source, iface, target_ip, source_asn, asn_path, country_path, hop_count,
           lag(asn_path)     OVER w AS prev_asn_path,
           lag(country_path) OVER w AS prev_country_path,
           lag(hop_count)    OVER w AS prev_hops
    FROM trace_run
    WHERE reached
    WINDOW w AS (PARTITION BY source, iface, source_asn, target_ip ORDER BY ts)
) x
WHERE prev_asn_path IS NOT NULL AND asn_path IS DISTINCT FROM prev_asn_path;

-- full display name of 1 measurement point, used in Grafana and deploy/sql/reports.sql:
--   netmon_display('laptop/vnpt', 'mon1')    -> 'Laptop · VNPT · mon1'
--   netmon_display('gp/JP/Tokyo', NULL)      -> 'Tokyo, Japan'   (probe location; 'Globalping' is the source_type)
CREATE OR REPLACE FUNCTION netmon_display(src TEXT, ifc TEXT) RETURNS TEXT LANGUAGE sql STABLE AS $$
    SELECT coalesce(
        (SELECT CASE WHEN s.kind = 'globalping' THEN s.display
                     ELSE s.display || coalesce(' · ' || NULLIF(ifc, ''), '') END
         FROM source s WHERE s.name = src),
        concat_ws(' · ', src, NULLIF(ifc, '')))
$$;

-- measurement source fields under the names used in reports (dimension table source)
CREATE OR REPLACE VIEW v_source AS
SELECT name AS source_key, initcap(kind) AS source_type, location AS source_location, display AS display_name,
       machine, isp, probe_country, probe_city, created_at
FROM source;

-- every measurement with all measurement source fields: Grafana and the reports read from here instead of joining themselves
CREATE OR REPLACE VIEW v_probe AS
SELECT p.ts, coalesce(initcap(s.kind), 'Local') AS source_type, s.location AS source_location,
       p.source AS source_key, p.source_asn,
       coalesce(CASE WHEN s.kind = 'globalping' THEN s.display ELSE s.display || coalesce(' · ' || p.iface, '') END,
                concat_ws(' · ', p.source, p.iface)) AS display_name,
       p.iface, p.target_name, p.target_ip, p.country, p.avg_ms, p.median_ms, p.jitter_ms, p.loss_pct, p.status,
       p.health, p.base_median_ms, p.base_jitter_ms
FROM probe_result p
LEFT JOIN source s ON s.name = p.source;

CREATE OR REPLACE VIEW v_trace AS
SELECT r.id, r.ts, coalesce(initcap(s.kind), 'Local') AS source_type, s.location AS source_location,
       r.source AS source_key, r.source_asn,
       coalesce(CASE WHEN s.kind = 'globalping' THEN s.display ELSE s.display || coalesce(' · ' || r.iface, '') END,
                concat_ws(' · ', r.source, r.iface)) AS display_name,
       r.iface, r.target_ip, r.tool, r.hop_count, r.reached, r.asn_path, r.country_path, r.bottleneck_hop,
       r.bottleneck_ms, r.dest_loss_pct, r.loss_start_hop, r.loss_where, r.loss_text
FROM trace_run r
LEFT JOIN source s ON s.name = r.source;
