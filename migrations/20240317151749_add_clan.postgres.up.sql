CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.clan_types(
    id uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    clan_type text NOT NULL,
    "description" text NOT NULL,
    ref_code varchar(20) NOT NULL,
    created_at timestamptz NULL,
    updated_at timestamptz NULL
);

CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.clans(
    id uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    "name" varchar(100) NOT NULL,
    display_name varchar(50) NOT NULL UNIQUE,
    slug varchar(20) NOT NULL UNIQUE,
    branding jsonb,
    email varchar(100),
    phone varchar(30),
    mission_statement text,
    mission_statement_summary text,
    additional_traits jsonb,
    date_established date,
    created_by uuid REFERENCES profiles(profile_id),
    clan_type_id uuid NOT NULL REFERENCES clan_types(id),
    is_public boolean NOT NULL DEFAULT TRUE,
    is_banned boolean NOT NULL DEFAULT FALSE,
    suspended_until timestamp with time zone,
    member_traits_url text NULL,
    preferences jsonb,
    created_at timestamptz NULL,
    updated_at timestamptz NULL
);

CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.clan_groups(
    id uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    "name" text NOT NULL,
    clan_id uuid NOT NULL REFERENCES clans(id),
    created_at timestamptz NULL,
    updated_at timestamptz NULL
);

CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.clan_members(
    id uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    clan_id uuid NOT NULL REFERENCES clans(id),
    date_joined date,
    additional_traits jsonb NULL,
    is_banned boolean NOT NULL DEFAULT FALSE,
    suspended_until timestamp with time zone,
    preferences jsonb,
    created_at timestamptz NULL,
    updated_at timestamptz NULL
);

CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.clan_group_assignments (
    id uuid NOT NULL PRIMARY KEY,
    clan_id uuid NOT NULL REFERENCES clans(id),
    clan_member_id uuid NOT NULL REFERENCES clan_members(id),
    clan_group_id uuid NOT NULL REFERENCES clan_groups(id),
    created_at timestamptz NULL,
    updated_at timestamptz NULL
);


CREATE OR REPLACE FUNCTION {{ index .Options "Namespace" }}.create_clan_helper()
    RETURNS TRIGGER
    AS $$
DECLARE
    m_id uuid;
BEGIN
    -- insert the user into the clan members
    INSERT INTO clan_members(id, clan_id)
        VALUES (NEW.created_by, NEW.clan_id)
    RETURNING
        id INTO m_id;
    --
    RETURN NEW;
END;
$$
LANGUAGE plpgsql;

-- Creating a trigger to invoke the trigger function AFTER INSERT on a specific table
CREATE TRIGGER {{ index .Options "Namespace" }}.on_clan_insert
    AFTER INSERT ON {{ index .Options "Namespace" }}.clans
    FOR EACH ROW
    EXECUTE FUNCTION {{ index .Options "Namespace" }}.create_clan_helper();

--
--
--
INSERT INTO clan_types(clan_type, description, ref_code)
    VALUES ('Undergraduate Association', 'A community for undergraduate students.', 'UA001'),
('Alumni Association', 'Connect with alumni and share experiences.', 'AA002'),
('Political Party', 'Engage in political discussions and activities.', 'PP003'),
('Tech Community', 'Discuss and collaborate on technology-related topics.', 'TC004'),
('Professional Body', 'Network with professionals in your industry.', 'PB005'),
('User Community', 'Build communities around your users and enhance user experience.', 'UC006'),
('Friends Community', 'A space for friends to connect and share moments.', 'FC008'),
('General Community', 'An open community for general discussions and interactions.', 'GC009'),
('Mentorship Program', 'Connect with mentors and mentees for guidance.', 'MP007');