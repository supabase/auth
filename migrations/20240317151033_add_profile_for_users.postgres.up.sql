CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.profiles (
    id uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    first_name varchar(32),
    last_name varchar(32),
    username varchar(32) UNIQUE,
    phone varchar(32),
    email varchar(32) NOT NULL UNIQUE,
    photo_uri text,
    birth_date date,
    bio text,
    is_banned boolean NOT NULL DEFAULT FALSE,
    suspended_until timestamp with time zone,
    user_id uuid NOT NULL REFERENCES {{ index .Options "Namespace" }}.users(id),
    preferences json,
    created_at timestamptz NULL,
    updated_at timestamptz NULL,
    CONSTRAINT username_length CHECK (char_length(username) >= 3)
);

CREATE OR REPLACE FUNCTION {{ index .Options "Namespace" }}.create_profile()
    RETURNS TRIGGER
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO profiles(user_id, email, preferences)
        VALUES(NEW.id, NEW.email, '{
            "personal": {
                "private_birth_date": false,
                "country": "NG",
                "currency": "NGN"
            },
            "notfications": {
                "enable_desktop_notifications": true,
                "enable_sounds": true
            },
            "chats": {
                "enter_sends": true
            },
            "clans": {}
        }');

    RETURN new;
END;
$$;

CREATE TRIGGER on_user_insert
    AFTER INSERT ON users
    FOR EACH ROW
    EXECUTE FUNCTION create_profile();

