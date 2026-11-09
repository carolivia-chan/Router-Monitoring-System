-- Measurement source fields (see v_source / v_probe in schema.sql):
--   source_type   Local | Globalping
--   source_point  = display_name  'Laptop · VNPT · mon1' | 'Tokyo, Japan'   (netmon_display(source, iface))
--   source_asn    = ASN of the network the measurement point sits in (AS45899 | AS2516)

-- R1. Compare the measurement points for each server (last 24 hours)
SELECT t.name AS server, s.source_type, netmon_display(h.source, h.iface) AS source_point,
       NULLIF(h.source_asn, '') AS source_asn,
       round(100.0 * sum(h.up_samples) / sum(h.samples), 2) AS availability_pct,
       round((percentile_cont(0.5) WITHIN GROUP (ORDER BY h.median_ms))::numeric, 1) AS median_ms,
       round(max(h.p95_ms)::numeric, 1) AS worst_p95_ms,
       round(avg(h.avg_loss_pct)::numeric, 2) AS loss_pct
FROM probe_hourly h JOIN target t ON t.ip = h.target_ip JOIN v_source s ON s.source_key = h.source
WHERE h.hour > now() - interval '24 hours'
GROUP BY 1, 2, 3, 4
ORDER BY 1, 2, median_ms;

-- R2. Peak hours: how much slower (%) each hour of the day is than the best hour of the same route (7 days)
WITH g AS (
    SELECT source, target_ip,
           extract(hour FROM hour AT TIME ZONE 'Asia/Ho_Chi_Minh')::int AS hour_of_day,
           percentile_cont(0.5) WITHIN GROUP (ORDER BY median_ms) AS med
    FROM probe_hourly
    WHERE hour > now() - interval '7 days'
    GROUP BY 1, 2, 3
)
SELECT hour_of_day,
       round(avg(100 * (med / NULLIF(min_med, 0) - 1))::numeric, 1) AS slower_than_best_hour_pct,
       count(*) AS routes
FROM (SELECT g.*, min(med) OVER (PARTITION BY source, target_ip) AS min_med FROM g) x
GROUP BY hour_of_day
ORDER BY hour_of_day;

-- R3. Top 10 worst routes in the last 24 hours (score = median + 10 x loss%, same formula as NetMon without the hop term)
SELECT t.name AS server, s.source_type, netmon_display(h.source, h.iface) AS source_point,
       NULLIF(h.source_asn, '') AS source_asn,
       round((percentile_cont(0.5) WITHIN GROUP (ORDER BY h.median_ms))::numeric, 1) AS median_ms,
       round(avg(h.avg_loss_pct)::numeric, 2) AS loss_pct,
       round(((percentile_cont(0.5) WITHIN GROUP (ORDER BY h.median_ms)) + 10 * avg(h.avg_loss_pct))::numeric, 1) AS score
FROM probe_hourly h JOIN target t ON t.ip = h.target_ip JOIN v_source s ON s.source_key = h.source
WHERE h.hour > now() - interval '24 hours'
GROUP BY 1, 2, 3, 4
ORDER BY score DESC NULLS FIRST
LIMIT 10;

-- R4. Route stability: number of AS path changes per day for each (measurement point, server) pair
SELECT (r.ts AT TIME ZONE 'Asia/Ho_Chi_Minh')::date AS day, s.source_type,
       netmon_display(r.source, r.iface) AS source_point, r.source_asn, r.target_ip,
       count(*) AS as_path_changes
FROM v_route_change r JOIN v_source s ON s.source_key = r.source
WHERE r.ts > now() - interval '7 days'
GROUP BY 1, 2, 3, 4, 5
ORDER BY 1 DESC, 6 DESC;

-- R5. Which ASN (network operator) is most often the bottleneck: the hop with the largest latency increase (7 days)
SELECT coalesce(h.asn, '(unknown)') AS asn, max(a.org) AS org,
       count(*) AS times_bottleneck,
       round(avg(r.bottleneck_ms)::numeric, 1) AS avg_increase_ms
FROM trace_run r
JOIN trace_hop h ON h.run_id = r.id AND h.hop = r.bottleneck_hop
LEFT JOIN asn a ON a.asn = h.asn
WHERE r.ts > now() - interval '7 days'
GROUP BY 1
ORDER BY 3 DESC
LIMIT 10;

-- R6. Where real packet loss happens (local / isp / transit / destination / unreachable / unknown), 7 days
SELECT loss_where AS location, count(*) AS traces,
       count(DISTINCT target_ip) AS servers,
       round(avg(dest_loss_pct)::numeric, 1) AS avg_dest_loss_pct
FROM trace_run
WHERE ts > now() - interval '7 days' AND loss_where IS NOT NULL
GROUP BY 1
ORDER BY 2 DESC;

-- R7. Number of incidents and mean time to recovery (MTTR) by alert kind and by status at alert time
-- (1 incident = from the first 'alert' message to the next 'recover' message; reminders / escalations belong to the
--  same incident; the real incident started ALERT_HOLD earlier)
WITH e AS (
    SELECT *, lag(state) OVER (PARTITION BY source, iface, target_ip, kind ORDER BY ts) AS prev_state
    FROM alert_event
    WHERE state IN ('alert', 'recover')
), s AS (
    SELECT e.*,
           (SELECT min(r.ts) FROM alert_event r
            WHERE r.state = 'recover' AND r.kind = e.kind AND r.ts > e.ts
              AND r.source IS NOT DISTINCT FROM e.source AND r.iface IS NOT DISTINCT FROM e.iface
              AND r.target_ip IS NOT DISTINCT FROM e.target_ip) AS recovered_at
    FROM e
    WHERE state = 'alert' AND prev_state IS DISTINCT FROM 'alert'
)
SELECT kind, coalesce(status, '-') AS status_at_alert, count(*) AS incidents, count(recovered_at) AS recovered,
       round((avg(extract(epoch FROM recovered_at - ts)) / 60)::numeric, 1) AS mttr_minutes
FROM s
GROUP BY 1, 2
ORDER BY incidents DESC;

-- R8. Daily availability (SLA) of each server and measurement point, 30 days
SELECT (h.hour AT TIME ZONE 'Asia/Ho_Chi_Minh')::date AS day, t.name AS server, s.source_type,
       netmon_display(h.source, h.iface) AS source_point,
       round(100.0 * sum(h.up_samples) / sum(h.samples), 3) AS availability_pct,
       sum(h.samples - h.up_samples) AS down_samples
FROM probe_hourly h JOIN target t ON t.ip = h.target_ip JOIN v_source s ON s.source_key = h.source
WHERE h.hour > now() - interval '30 days'
GROUP BY 1, 2, 3, 4
ORDER BY 1 DESC, 5;

-- R9. Network Health over the last 24 hours: % of probe rounds in each state for every route (measurement point ->
-- server), worst routes first (see monitor/health.py: DEGRADED = 1 abnormal metric, UNSTABLE = 2 or more)
SELECT * FROM (
    SELECT target_name AS server, display_name AS source_point,
           round(100.0 * count(*) FILTER (WHERE health = 'HEALTHY')  / count(*), 1) AS healthy_pct,
           round(100.0 * count(*) FILTER (WHERE health = 'DEGRADED') / count(*), 1) AS degraded_pct,
           round(100.0 * count(*) FILTER (WHERE health = 'UNSTABLE') / count(*), 1) AS unstable_pct,
           round(100.0 * count(*) FILTER (WHERE health = 'DOWN')     / count(*), 1) AS down_pct,
           round(100.0 * count(*) FILTER (WHERE health = 'UNKNOWN')  / count(*), 1) AS unknown_pct,
           round(avg(median_ms - base_median_ms)::numeric, 1) AS avg_latency_above_baseline_ms
    FROM v_probe
    WHERE ts > now() - interval '24 hours' AND health IS NOT NULL
    GROUP BY 1, 2
) x
ORDER BY unstable_pct + down_pct DESC, degraded_pct DESC
LIMIT 30;
