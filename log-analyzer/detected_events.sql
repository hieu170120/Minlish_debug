
SELECT
    timestamp,
    result,
    process_result,
    local_service
FROM security_events
WHERE result = 'DETECTED'
ORDER BY timestamp ASC;
