-- set idle_in_transaction_session_timeout to 1min

ALTER ROLE current_user SET idle_in_transaction_session_timeout TO 60000;
