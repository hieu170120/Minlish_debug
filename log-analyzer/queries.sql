
SELECT
    result,
    COUNT(*) AS total
FROM security_events
GROUP BY result
ORDER BY total DESC;
