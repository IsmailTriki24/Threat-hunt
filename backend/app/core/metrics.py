from prometheus_client import Counter, Histogram

HTTP_REQUESTS = Counter("http_requests_total", "HTTP requests", ["method", "path", "status"])
HTTP_LATENCY = Histogram("http_request_duration_seconds", "HTTP request latency", ["method", "path"])
EVENTS_INGESTED = Counter("events_ingested_total", "Events accepted for indexing", ["tenant_id"])
EVENTS_REJECTED = Counter("events_rejected_total", "Events rejected at ingestion", ["reason"])
SEARCHES = Counter("event_searches_total", "Event searches executed")
LOGIN_ATTEMPTS = Counter("auth_login_attempts_total", "Login attempts", ["outcome"])
