package models

import "time"

// create table if not exists public.tenants (
//     id text primary key,
//     created_at timestamp with time zone default timezone('utc'::text, now()) not null,
//     updated_at timestamp with time zone default timezone('utc'::text, now()) not null,
//     "DATABASE_URL" text not null,
//     "DATABASE_MAX_POOL_SIZE" integer default 0 not null,
//     "DATABASE_MAX_IDLE_POOL_SIZE" integer default 2 not null,
//     "DATABASE_CONN_MAX_LIFETIME" text default '0' not null ,
//     "DATABASE_CONN_MAX_IDLE_TIME" text default '0' not null,
//     "DATABASE_HEALTH_CHECK_PERIOD" text default '0' not null,
//     "DB_MAX_POOL_SIZE" smallint default 10 not null,

//     -- this should be the domain used for constructing the API_EXTERNAL_URL and OAuth Redirect URI
//     "TENANT_DOMAIN" text not null,
//     "JWT_SECRET" text not null,

//     "SITE_URL" text default 'http://localhost:3000'::text not null,
//     "URI_ALLOW_LIST" text default ''::text,
//     "DISABLE_SIGNUP" boolean default false not null,
//     "RATE_LIMIT_HEADER" text,
//     "JWT_EXP" integer default 3600 not null,
//     "JWT_AUD" text default 'authenticated'::text not null,
//     "JWT_DEFAULT_GROUP_NAME" text default 'authenticated'::text not null,
//     "JWT_ADMIN_ROLES" text not null,
//     "REFRESH_TOKEN_ROTATION_ENABLED" boolean default true,
//     "PASSWORD_MIN_LENGTH" smallint default 6,

//     -- SMS settings
//     "EXTERNAL_PHONE_ENABLED" boolean default false not null,
//     "SMS_AUTOCONFIRM" boolean default false not null,
//     "SMS_MAX_FREQUENCY" smallint default 5 not null,
//     "SMS_OTP_EXP" integer default 60 not null,
//     "SMS_OTP_LENGTH" smallint default 6 not null,
//     "SMS_PROVIDER" text,
//     "SMS_TEMPLATE" text default 'Your code is \{\{ .Code \}\}'::text,

//     -- SMS providers
//     "SMS_TWILIO_ACCOUNT_SID" text,
//     "SMS_TWILIO_AUTH_TOKEN" text,
//     "SMS_TWILIO_MESSAGE_SERVICE_SID" text,
//     "SMS_MESSAGEBIRD_ACCESS_KEY" text,
//     "SMS_MESSAGEBIRD_ORIGINATOR" text,
//     "SMS_VONAGE_API_KEY" text,
//     "SMS_VONAGE_API_SECRET" text,
//     "SMS_VONAGE_FROM" text,
//     "SMS_TEXTLOCAL_API_KEY" text,
//     "SMS_TEXTLOCAL_SENDER" text,

//     -- Email settings
//     "EXTERNAL_EMAIL_ENABLED" boolean default true not null,
//     "SMTP_ADMIN_EMAIL" text,
//     "SMTP_HOST" text,
//     "SMTP_PORT" text,
//     "SMTP_USER" text,
//     "SMTP_PASS" text,
//     "SMTP_MAX_FREQUENCY" smallint default 60 not null,
//     "SMTP_SENDER_NAME" text,
//     -- "SMTP_PASS_ENCRYPTED" text,

//     "MAILER_AUTOCONFIRM" boolean default false not null,
//     "MAILER_OTP_EXP" integer default 86400 not null,
//     "MAILER_SECURE_EMAIL_CHANGE_ENABLED" boolean default true not null,
//     "MAILER_URLPATHS_INVITE" text default '/auth/v1/verify'::text not null,
//     "MAILER_URLPATHS_CONFIRMATION" text default '/auth/v1/verify'::text not null,
//     "MAILER_URLPATHS_RECOVERY" text default '/auth/v1/verify'::text not null,
//     "MAILER_URLPATHS_EMAIL_CHANGE" text default '/auth/v1/verify'::text not null,
//     "MAILER_SUBJECTS_INVITE" text default 'You have been invited'::text not null,
//     "MAILER_SUBJECTS_CONFIRMATION" text default 'Confirm Your Signup'::text not null,
//     "MAILER_SUBJECTS_RECOVERY" text default 'Reset Your Password'::text not null,
//     "MAILER_SUBJECTS_EMAIL_CHANGE" text default 'Confirm Email Change'::text not null,
//     "MAILER_TEMPLATES_INVITE" text,
//     "MAILER_TEMPLATES_INVITE_CONTENT" text default '<h2>You have been invited</h2>

// <p>You have been invited to create a user on \{\{ .SiteURL \}\}. Follow this link to accept the invite:</p>
// <p><a href="\{\{ .ConfirmationURL \}\}">Accept the invite</a></p>'::text not null,
//     "MAILER_TEMPLATES_CONFIRMATION" text,
//     "MAILER_TEMPLATES_CONFIRMATION_CONTENT" text default '<h2>Confirm your signup</h2>

// <p>Follow this link to confirm your user:</p>
// <p><a href="\{\{ .ConfirmationURL \}\}">Confirm your mail</a></p>'::text not null,
//     "MAILER_TEMPLATES_RECOVERY" text,
//     "MAILER_TEMPLATES_RECOVERY_CONTENT" text default '<h2>Reset Password</h2>

// <p>Follow this link to reset the password for your user:</p>
// <p><a href="\{\{ .ConfirmationURL \}\}">Reset Password</a></p>'::text not null,
//     "MAILER_TEMPLATES_EMAIL_CHANGE" text,
//     "MAILER_TEMPLATES_EMAIL_CHANGE_CONTENT" text default '<h2>Confirm Change of Email</h2>

// <p>Follow this link to confirm the update of your email from \{\{ .Email \}\} to \{\{ .NewEmail \}\}:</p>
// <p><a href="\{\{ .ConfirmationURL \}\}">Change Email</a></p>'::text not null,
//     "MAILER_SUBJECTS_MAGIC_LINK" text default 'Your Magic Link'::text not null,
//     "MAILER_TEMPLATES_MAGIC_LINK" text,
//     "MAILER_TEMPLATES_MAGIC_LINK_CONTENT" text default '<h2>Magic Link</h2>

// <p>Follow this link to login:</p>
// <p><a href="\{\{ .ConfirmationURL \}\}">Log In</a></p>'::text not null,

//     -- Captcha settings
//     "SECURITY_CAPTCHA_ENABLED" boolean default false not null,
//     "SECURITY_CAPTCHA_PROVIDER" text,
//     "SECURITY_CAPTCHA_SECRET" text,
//     "SECURITY_CAPTCHA_TIMEOUT" text default '10s',

//     -- Misc settings
//     "SECURITY_UPDATE_PASSWORD_REQUIRE_REAUTHENTICATION" boolean default false not null,
//     "SECURITY_REFRESH_TOKEN_REUSE_INTERVAL" integer default 10 not null,

//     -- Rate limits
//     "RATE_LIMIT_VERIFY" integer default 30 not null,
//     "RATE_LIMIT_TOKEN_REFRESH" integer default 150 not null,
//     "RATE_LIMIT_EMAIL_SENT" smallint default 30 not null,
//     "RATE_LIMIT_SMS_SENT" smallint default 30 not null,

//     -- MFA
//     "MAX_ENROLLED_FACTORS" integer default 10 not null,

//     -- OAuth providers
//     "EXTERNAL_APPLE_ENABLED" boolean default false not null,
//     "EXTERNAL_APPLE_CLIENT_ID" text,
//     "EXTERNAL_APPLE_SECRET" text,

//     "EXTERNAL_AZURE_ENABLED" boolean default false not null,
//     "EXTERNAL_AZURE_CLIENT_ID" text,
//     "EXTERNAL_AZURE_SECRET" text,
//     "EXTERNAL_AZURE_URL" text,

//     "EXTERNAL_BITBUCKET_ENABLED" boolean default false not null,
//     "EXTERNAL_BITBUCKET_CLIENT_ID" text,
//     "EXTERNAL_BITBUCKET_SECRET" text,

//     "EXTERNAL_DISCORD_ENABLED" boolean default false not null,
//     "EXTERNAL_DISCORD_CLIENT_ID" text,
//     "EXTERNAL_DISCORD_SECRET" text,

//     "EXTERNAL_FACEBOOK_ENABLED" boolean default false not null,
//     "EXTERNAL_FACEBOOK_CLIENT_ID" text,
//     "EXTERNAL_FACEBOOK_SECRET" text,

//     "EXTERNAL_GOOGLE_ENABLED" boolean default false not null,
//     "EXTERNAL_GOOGLE_CLIENT_ID" text,
//     "EXTERNAL_GOOGLE_SECRET" text,

//     "EXTERNAL_GITHUB_ENABLED" boolean default false not null,
//     "EXTERNAL_GITHUB_CLIENT_ID" text,
//     "EXTERNAL_GITHUB_SECRET" text,

//     "EXTERNAL_GITLAB_ENABLED" boolean default false not null,
//     "EXTERNAL_GITLAB_CLIENT_ID" text,
//     "EXTERNAL_GITLAB_SECRET" text,
//     "EXTERNAL_GITLAB_URL" text,

//     "EXTERNAL_KEYCLOAK_ENABLED" boolean default false not null,
//     "EXTERNAL_KEYCLOAK_CLIENT_ID" text,
//     "EXTERNAL_KEYCLOAK_SECRET" text,
//     "EXTERNAL_KEYCLOAK_URL" text,

//     "EXTERNAL_LINKEDIN_ENABLED" boolean default false not null,
//     "EXTERNAL_LINKEDIN_CLIENT_ID" text,
//     "EXTERNAL_LINKEDIN_SECRET" text,

//     "EXTERNAL_NOTION_ENABLED" boolean default false not null,
//     "EXTERNAL_NOTION_CLIENT_ID" text,
//     "EXTERNAL_NOTION_SECRET" text,

//     "EXTERNAL_TWITCH_ENABLED" boolean default false not null,
//     "EXTERNAL_TWITCH_CLIENT_ID" text,
//     "EXTERNAL_TWITCH_SECRET" text,

//     "EXTERNAL_TWITTER_ENABLED" boolean default false not null,
//     "EXTERNAL_TWITTER_CLIENT_ID" text,
//     "EXTERNAL_TWITTER_SECRET" text,

//     "EXTERNAL_SPOTIFY_ENABLED" boolean default false not null,
//     "EXTERNAL_SPOTIFY_CLIENT_ID" text,
//     "EXTERNAL_SPOTIFY_SECRET" text,

//     "EXTERNAL_SLACK_ENABLED" boolean default false not null,
//     "EXTERNAL_SLACK_CLIENT_ID" text,
//     "EXTERNAL_SLACK_SECRET" text,

//     "EXTERNAL_WORKOS_ENABLED" boolean default false not null,
//     "EXTERNAL_WORKOS_CLIENT_ID" text,
//     "EXTERNAL_WORKOS_SECRET" text,
//     "EXTERNAL_WORKOS_URL" text,

//     "EXTERNAL_ZOOM_ENABLED" boolean default false not null,
//     "EXTERNAL_ZOOM_CLIENT_ID" text,
//     "EXTERNAL_ZOOM_SECRET" text,

//     CONSTRAINT max_jwt CHECK (("JWT_EXP" <= 604800))
// );

type Tenant struct {
	ID                  string    `json:"id" db:"id"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time `json:"updated_at" db:"updated_at"`
	DatabaseURL         string    `json:"database_url" db:"database_url"`
	DatabaseMaxPoolSize int       `json:"database_max_pool_size" db:"database_max_pool_size"`
	SiteURL             string    `json:"site_url" db:"site_url"`
}

func (Tenant) TableName() string {
	tableName := "tenants"
	return tableName
}
