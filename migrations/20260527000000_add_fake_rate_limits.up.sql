CREATE TABLE IF NOT EXISTS fake_rate_limits (
    email_hash VARCHAR(64) PRIMARY KEY,
    last_request_at TIMESTAMP WITH TIME ZONE NOT NULL
);
