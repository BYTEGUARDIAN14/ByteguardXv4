-- ByteGuardX Database Optimization Script
-- Indexes, partitioning, and performance optimizations

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS btree_gin;

-- Performance indexes for scan_results table
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_results_user_id 
ON scan_results(user_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_results_created_at 
ON scan_results(created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_results_status 
ON scan_results(status);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_results_scan_type 
ON scan_results(scan_type);

-- Composite index for common queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_results_user_status_date 
ON scan_results(user_id, status, created_at DESC);

-- Performance indexes for findings table
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_scan_id 
ON findings(scan_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_severity 
ON findings(severity);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_finding_type 
ON findings(finding_type);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_file_path 
ON findings USING gin(file_path gin_trgm_ops);

-- Composite index for findings queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_scan_severity_type 
ON findings(scan_id, severity, finding_type);

-- Performance indexes for audit_logs table
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_user_id 
ON audit_logs(user_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_created_at 
ON audit_logs(created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_action 
ON audit_logs(action);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_ip_address 
ON audit_logs(ip_address);

-- Composite index for security monitoring
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_action_date_ip 
ON audit_logs(action, created_at DESC, ip_address);

-- Performance indexes for users table
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email 
ON users(email);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_last_login 
ON users(last_login DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_is_active 
ON users(is_active);

-- Performance indexes for plugin_executions table
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_plugin_executions_plugin_id 
ON plugin_executions(plugin_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_plugin_executions_created_at 
ON plugin_executions(created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_plugin_executions_status 
ON plugin_executions(status);

-- Table partitioning for audit_logs (by month)
-- This helps with large audit log tables
DO $$
DECLARE
    start_date DATE;
    end_date DATE;
    partition_name TEXT;
BEGIN
    -- Create partitioned audit_logs table if not exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_name = 'audit_logs_partitioned'
    ) THEN
        -- Create new partitioned table
        CREATE TABLE audit_logs_partitioned (
            LIKE audit_logs INCLUDING ALL
        ) PARTITION BY RANGE (created_at);
        
        -- Create partitions for current and next 12 months
        FOR i IN 0..12 LOOP
            start_date := date_trunc('month', CURRENT_DATE) + (i || ' months')::INTERVAL;
            end_date := start_date + '1 month'::INTERVAL;
            partition_name := 'audit_logs_' || to_char(start_date, 'YYYY_MM');
            
            EXECUTE format('
                CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_logs_partitioned
                FOR VALUES FROM (%L) TO (%L)',
                partition_name, start_date, end_date
            );
        END LOOP;
    END IF;
END $$;

-- Table partitioning for findings (by scan_id range)
-- This helps with large findings tables
DO $$
DECLARE
    partition_name TEXT;
BEGIN
    -- Create partitioned findings table if not exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_name = 'findings_partitioned'
    ) THEN
        -- Create new partitioned table
        CREATE TABLE findings_partitioned (
            LIKE findings INCLUDING ALL
        ) PARTITION BY RANGE (scan_id);
        
        -- Create partitions for scan_id ranges
        FOR i IN 0..9 LOOP
            partition_name := 'findings_part_' || i;
            
            EXECUTE format('
                CREATE TABLE IF NOT EXISTS %I PARTITION OF findings_partitioned
                FOR VALUES FROM (%s) TO (%s)',
                partition_name, i * 100000, (i + 1) * 100000
            );
        END LOOP;
        
        -- Default partition for higher scan_ids
        CREATE TABLE IF NOT EXISTS findings_part_default PARTITION OF findings_partitioned
        DEFAULT;
    END IF;
END $$;

-- Materialized view for scan statistics
CREATE MATERIALIZED VIEW IF NOT EXISTS scan_statistics AS
SELECT 
    DATE(created_at) as scan_date,
    scan_type,
    status,
    COUNT(*) as scan_count,
    AVG(total_findings) as avg_findings,
    AVG(EXTRACT(EPOCH FROM (completed_at - created_at))) as avg_duration_seconds
FROM scan_results 
WHERE created_at >= CURRENT_DATE - INTERVAL '90 days'
GROUP BY DATE(created_at), scan_type, status
ORDER BY scan_date DESC;

-- Index on materialized view
CREATE INDEX IF NOT EXISTS idx_scan_statistics_date 
ON scan_statistics(scan_date DESC);

-- Materialized view for security metrics
CREATE MATERIALIZED VIEW IF NOT EXISTS security_metrics AS
SELECT 
    DATE(created_at) as metric_date,
    action,
    COUNT(*) as event_count,
    COUNT(DISTINCT user_id) as unique_users,
    COUNT(DISTINCT ip_address) as unique_ips
FROM audit_logs 
WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY DATE(created_at), action
ORDER BY metric_date DESC;

-- Index on security metrics view
CREATE INDEX IF NOT EXISTS idx_security_metrics_date 
ON security_metrics(metric_date DESC);

-- Function to refresh materialized views
CREATE OR REPLACE FUNCTION refresh_statistics_views()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY scan_statistics;
    REFRESH MATERIALIZED VIEW CONCURRENTLY security_metrics;
END;
$$ LANGUAGE plpgsql;

-- Automated cleanup function for old data
CREATE OR REPLACE FUNCTION cleanup_old_data()
RETURNS void AS $$
DECLARE
    cutoff_date DATE;
    deleted_count INTEGER;
BEGIN
    -- Delete audit logs older than 180 days
    cutoff_date := CURRENT_DATE - INTERVAL '180 days';
    
    DELETE FROM audit_logs 
    WHERE created_at < cutoff_date;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RAISE NOTICE 'Deleted % old audit log records', deleted_count;
    
    -- Delete completed scans older than 90 days (keep failed scans longer)
    cutoff_date := CURRENT_DATE - INTERVAL '90 days';
    
    DELETE FROM scan_results 
    WHERE created_at < cutoff_date 
    AND status = 'completed';
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RAISE NOTICE 'Deleted % old scan records', deleted_count;
    
    -- Vacuum and analyze tables
    VACUUM ANALYZE audit_logs;
    VACUUM ANALYZE scan_results;
    VACUUM ANALYZE findings;
END;
$$ LANGUAGE plpgsql;

-- Performance monitoring view
CREATE OR REPLACE VIEW slow_queries AS
SELECT 
    query,
    calls,
    total_time,
    mean_time,
    rows,
    100.0 * shared_blks_hit / nullif(shared_blks_hit + shared_blks_read, 0) AS hit_percent
FROM pg_stat_statements 
ORDER BY total_time DESC 
LIMIT 20;

-- Database size monitoring view
CREATE OR REPLACE VIEW database_sizes AS
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
    pg_total_relation_size(schemaname||'.'||tablename) as size_bytes
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY size_bytes DESC;

-- Index usage monitoring view
CREATE OR REPLACE VIEW index_usage AS
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_tup_read,
    idx_tup_fetch,
    idx_scan,
    pg_size_pretty(pg_relation_size(indexrelid)) as index_size
FROM pg_stat_user_indexes 
ORDER BY idx_scan DESC;

-- Connection monitoring view
CREATE OR REPLACE VIEW connection_stats AS
SELECT 
    state,
    COUNT(*) as connection_count,
    MAX(now() - state_change) as max_duration
FROM pg_stat_activity 
WHERE state IS NOT NULL
GROUP BY state;

-- Automated maintenance schedule
-- This would typically be set up as a cron job or scheduled task

-- Daily cleanup at 2 AM
-- 0 2 * * * psql -d byteguardx -c "SELECT cleanup_old_data();"

-- Refresh statistics views every hour
-- 0 * * * * psql -d byteguardx -c "SELECT refresh_statistics_views();"

-- Weekly VACUUM ANALYZE
-- 0 3 * * 0 psql -d byteguardx -c "VACUUM ANALYZE;"

-- Performance tuning settings (add to postgresql.conf)
/*
# Memory settings
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB
work_mem = 4MB

# Checkpoint settings
checkpoint_completion_target = 0.9
wal_buffers = 16MB

# Query planner settings
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200

# Connection settings
max_connections = 200

# Logging settings
log_min_duration_statement = 1000
log_checkpoints = on
log_connections = on
log_disconnections = on
log_lock_waits = on

# Monitoring
shared_preload_libraries = 'pg_stat_statements'
pg_stat_statements.track = all
*/
