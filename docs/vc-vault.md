# Credential vault

Certify keeps a copy of every credential it signs, so a wallet can download **the same credential** later
(eSignet OTP login -> vc-store service) instead of triggering a new issuance.

```
Issue    : /issuance/credential -> sign -> CredentialVaultService.store() -> vc_vault.credential   (same transaction of work:
           if the insert fails the credential is NOT returned)
Download : wallet -> Mimoto -> eSignet (credential id + OTP) -> vc-store service -> vc_vault.credential
```

## Enable

```properties
mosip.certify.vc-vault.enabled=true
# base64 of 32 random bytes:  openssl rand -base64 32     (vc-store service must use the SAME key)
mosip.certify.vc-vault.encryption-key=...
# REQUIRED when enabled: gives every credential an id = prefix + claim code (e.g. urn:openg2p:credential:K7QM-2XPD-9TVR)
mosip.certify.data-provider-plugin.id-field-prefix-uri=urn:openg2p:credential:
# claims read from the data provider response (defaults shown)
mosip.certify.vc-vault.record-id-claim=functionalRecordId
mosip.certify.vc-vault.phone-claim=phoneNumbers
mosip.certify.vc-vault.email-claim=email
# local development only: store VC and phone in clear text
# mosip.certify.vc-vault.allow-plaintext=true
```

Certify refuses to start with the vault enabled if the id prefix or the encryption key is missing.

## Credential template

The credential must carry its id, otherwise nobody can tell the holder what to type. Add to the
credential's `vcTemplateJson` (inside the top-level object):

```
"id": "${credentialId}",
```

## Database

Run `db_scripts/inji_certify/ddl/certify-vc_vault.sql` on the `inji_certify` database (already listed in
`ddl.sql` for new installs). It creates the `vc_vault` schema with two tables and grants:

| Role | Access |
|---|---|
| Certify's role: `certifyuser`, or `inji_certify_user` as used by OpenG2P (the one in `spring.datasource.username`) | `INSERT` on `vc_vault.credential` only |
| `vaultuser` (vc-store service; create it yourself) | `SELECT, UPDATE` on `credential`, `SELECT, INSERT, UPDATE` on `otp` |

## Where the OTP goes

The vault keeps the holder's email and phone (encrypted) from the claims Certify receives. The vc-store service
sends the OTP **by email when an email is stored, otherwise by SMS**. The claims only contain an email if the
data source supplies one: the portal projects every column of the VC's registry view into the claims, so add the
email column to that view (and to `claim_columns`, if the VC definition lists them) and set `email-claim` to its
name. An email claim may be a plain address, a list of addresses, or a list like
`[{'type': 'personal', 'email': 'a@b.com', 'is_primary': True}]`. Like the phone, it is not part of the signed VC
unless the credential template maps it.

## Claim code

With the vault enabled, Certify generates the credential id itself: a short claim code `XXXX-XXXX-XXXX`
(32 symbols, no I/O/0/1, 60 bits). It is the vault key, the suffix of the VC `id` and the ledger credential id,
and the code the farmer types in eSignet. It is an identifier, not a secret: the OTP is the second factor.
If two credentials ever drew the same code (about 1 in 10^18 per pair) the insert fails and issuance returns an
error, so the client simply retries.

## What is stored

`credential_id` (the claim code, e.g. `K7QM-2XPD-9TVR`), `functional_record_id`, `config_id`, `credential_types`, `format`, the signed VC and the
registered phone (both AES-256-GCM, credential id bound in as associated data), `holder_id`, `issuer_id`, the registered email (encrypted) with a masked copy,
`status` (`ACTIVE`/`REVOKED`/`EXPIRED`), `issued_at`, `expires_at`, download counters.
A holder can have many credentials; nothing is replaced when another one is issued.

## Notes

- The ledger row is written *before* signing (existing behaviour). If the vault insert then fails, the ledger
  shows an issuance for a credential nobody received.
- The vault holds personal data (VC contents, phone numbers). Back it up and restrict it like the key store.
