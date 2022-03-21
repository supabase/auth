-- set idle_in_transaction_session_timeout to 5min

ALTER ROLE current_user SET idle_in_transaction_session_timeout TO 300000;
