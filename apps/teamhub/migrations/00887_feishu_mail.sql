-- +goose Up
-- The Feishu authorization behind one external_connection_upstreams row. A
-- row starts with only the PKCE verifier of its consent page and holds the
-- user's tokens, sealed, once the code is exchanged. Feishu rotates refresh
-- tokens on every use, so a refresh replaces both tokens in one update. The
-- app the tokens were issued to is kept: tokens of another app cannot refresh.
-- TeamHub authorizes Feishu Mail with the deployment's Feishu custom app itself,
-- not through Composio, because Feishu serves its mail APIs to custom apps only.
CREATE TABLE feishu_upstream_tokens (
    upstream_id text PRIMARY KEY REFERENCES external_connection_upstreams(upstream_id) ON DELETE CASCADE,
    region text NOT NULL CHECK (region IN ('feishu', 'lark')),
    app_id text NOT NULL,
    code_verifier_ciphertext bytea NOT NULL,
    access_token_ciphertext bytea,
    refresh_token_ciphertext bytea,
    access_expires_at timestamp with time zone,
    refresh_expires_at timestamp with time zone,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    authorized_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT feishu_upstream_tokens_authorized_check CHECK (
        (access_token_ciphertext IS NULL) = (refresh_token_ciphertext IS NULL)
        AND (access_token_ciphertext IS NULL) = (access_expires_at IS NULL)
        AND (access_token_ciphertext IS NULL) = (refresh_expires_at IS NULL)
        AND (access_token_ciphertext IS NULL) = (authorized_at IS NULL)
    )
);

-- AnotherMe may watch a Feishu Mail inbox like a Gmail or Outlook one.
ALTER TABLE room_routine_listeners DROP CONSTRAINT room_routine_listeners_kind_check;
ALTER TABLE room_routine_listeners ADD CONSTRAINT room_routine_listeners_kind_check CHECK (
    kind = ANY (ARRAY['slack'::text, 'gmail'::text, 'outlook'::text, 'gcal'::text, 'outlook_calendar'::text, 'feishu_mail'::text])
);

-- +goose Down
DELETE FROM room_routine_listeners WHERE kind = 'feishu_mail';
ALTER TABLE room_routine_listeners DROP CONSTRAINT room_routine_listeners_kind_check;
ALTER TABLE room_routine_listeners ADD CONSTRAINT room_routine_listeners_kind_check CHECK (
    kind = ANY (ARRAY['slack'::text, 'gmail'::text, 'outlook'::text, 'gcal'::text, 'outlook_calendar'::text])
);
DROP TABLE feishu_upstream_tokens;
