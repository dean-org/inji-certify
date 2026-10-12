-- ---------------------------------------------------------------------------------------------------
-- Credential vault: a copy of every signed credential, written by Certify right after signing and
-- served to wallets by the vc-store service after an eSignet OTP login.
-- Lives in its own schema of the inji_certify database so Certify's role can be limited to INSERT.
-- ---------------------------------------------------------------------------------------------------

CREATE SCHEMA IF NOT EXISTS vc_vault;

CREATE TABLE IF NOT EXISTS vc_vault.credential (
    credential_id         VARCHAR(64)  PRIMARY KEY,          -- claim code, e.g. K7QM-2XPD-9TVR (also the VC id suffix)
    functional_record_id  VARCHAR(100) NOT NULL,             -- e.g. FR-... (claim: vc-vault.record-id-claim)
    config_id             VARCHAR(200) NOT NULL,             -- credential_configuration_id
    credential_types      TEXT         NOT NULL,             -- comma-joined VC types
    format                VARCHAR(30)  NOT NULL,             -- ldp_vc, vc+sd-jwt, ...
    vc_payload            TEXT         NOT NULL,             -- signed VC; AES-GCM ciphertext when encrypted = TRUE
    encrypted             BOOLEAN      NOT NULL,
    phone_payload         TEXT,                              -- registered phone (E.164) for the OTP, encrypted like vc_payload
    phone_masked          VARCHAR(32),                       -- '+251******795': safe to show and log
    email_payload         TEXT,                              -- registered email for the OTP, encrypted like vc_payload
    email_masked          VARCHAR(64),                       -- 'r***@example.com': safe to show and log
    holder_id             TEXT,                              -- did:jwk the credential was bound to at issuance
    issuer_id             TEXT,
    status                VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE'
                          CHECK (status IN ('ACTIVE','REVOKED','EXPIRED')),
    issued_at             TIMESTAMPTZ,
    expires_at            TIMESTAMPTZ,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    revoked_at            TIMESTAMPTZ,
    download_count        INTEGER      NOT NULL DEFAULT 0,
    last_downloaded_at    TIMESTAMPTZ
);

-- Installs that created the table before email support get the columns here (no-op otherwise).
ALTER TABLE vc_vault.credential ADD COLUMN IF NOT EXISTS email_payload TEXT;
ALTER TABLE vc_vault.credential ADD COLUMN IF NOT EXISTS email_masked  VARCHAR(64);

-- A holder can have many credentials (several crop credentials, re-issued cards...): no uniqueness here.
CREATE INDEX IF NOT EXISTS ix_vault_record_type
    ON vc_vault.credential (functional_record_id, config_id, status);

-- OTP challenges used by the eSignet plugin through the vc-store service. Only an HMAC of the OTP is stored.
CREATE TABLE IF NOT EXISTS vc_vault.otp (
    otp_id         BIGSERIAL    PRIMARY KEY,
    credential_id  VARCHAR(64)  NOT NULL REFERENCES vc_vault.credential (credential_id),
    otp_hash       TEXT         NOT NULL,
    expires_at     TIMESTAMPTZ  NOT NULL,
    attempts       INTEGER      NOT NULL DEFAULT 0,
    consumed       BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_vault_otp_lookup ON vc_vault.otp (credential_id, created_at DESC);

-- Least privilege.
--   Certify's role : INSERT only (Certify writes; it never needs to read VCs back).
--                    Granted to whichever of these exists: certifyuser (default of these db_scripts) or
--                    inji_certify_user (OpenG2P deployments). It must be the role in spring.datasource.username:
--                    if neither exists a WARNING is raised and you must run the two GRANTs yourself, otherwise
--                    every issuance fails once the vault is enabled.
--   vaultuser      : the vc-store service (create this role in role_dbuser.sql or by hand; skipped if absent)
DO $$
DECLARE
    r       TEXT;
    granted BOOLEAN := FALSE;
BEGIN
    FOREACH r IN ARRAY ARRAY['certifyuser', 'inji_certify_user'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('GRANT USAGE ON SCHEMA vc_vault TO %I', r);
            EXECUTE format('GRANT INSERT ON vc_vault.credential TO %I', r);
            RAISE NOTICE 'vc_vault: granted INSERT to Certify role %', r;
            granted := TRUE;
        END IF;
    END LOOP;
    IF NOT granted THEN
        RAISE WARNING 'vc_vault: no Certify database role found (certifyuser / inji_certify_user). Run: GRANT USAGE ON SCHEMA vc_vault TO <spring.datasource.username>; GRANT INSERT ON vc_vault.credential TO <spring.datasource.username>;';
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vaultuser') THEN
        GRANT USAGE ON SCHEMA vc_vault TO vaultuser;
        GRANT SELECT, UPDATE ON vc_vault.credential TO vaultuser;
        GRANT SELECT, INSERT, UPDATE ON vc_vault.otp TO vaultuser;
        GRANT USAGE, SELECT ON SEQUENCE vc_vault.otp_otp_id_seq TO vaultuser;
    END IF;
END
$$;
