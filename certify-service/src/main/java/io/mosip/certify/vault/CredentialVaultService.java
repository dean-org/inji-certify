package io.mosip.certify.vault;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.exception.CertifyException;
import java.sql.Types;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Keeps a copy of every signed credential in the `vc_vault` schema, so a wallet download (eSignet OTP
 * login -> vc-store service) returns the SAME credential instead of triggering a new issuance.
 *
 * The row key is the credential id: a short claim code (e.g. K7QM-2XPD-9TVR) generated before signing, so
 * it is also the id Certify puts into the VC and the ledger, and the code the holder types in eSignet.
 */
@Service
public class CredentialVaultService {
    private static final Logger log = LoggerFactory.getLogger(CredentialVaultService.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    static final String INSERT_SQL =
            "INSERT INTO vc_vault.credential (credential_id, functional_record_id, config_id, credential_types, "
                    + "format, vc_payload, encrypted, phone_payload, phone_masked, email_payload, email_masked, "
                    + "holder_id, issuer_id, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    private static final int[] INSERT_TYPES = {
        Types.VARCHAR, Types.VARCHAR, Types.VARCHAR, Types.VARCHAR,
        Types.VARCHAR, Types.VARCHAR, Types.BOOLEAN, Types.VARCHAR, Types.VARCHAR, Types.VARCHAR, Types.VARCHAR,
        Types.VARCHAR, Types.VARCHAR,
        Types.TIMESTAMP_WITH_TIMEZONE, Types.TIMESTAMP_WITH_TIMEZONE
    };

    private final boolean enabled;
    private final JdbcTemplate jdbc;
    private final VaultCrypto crypto;
    private final String recordIdClaim;
    private final String phoneClaim;
    private final String emailClaim;

    public CredentialVaultService(
            DataSource dataSource,
            @Value("${mosip.certify.vc-vault.enabled:false}") boolean enabled,
            @Value("${mosip.certify.vc-vault.encryption-key:}") String encryptionKey,
            @Value("${mosip.certify.vc-vault.allow-plaintext:false}") boolean allowPlaintext,
            @Value("${mosip.certify.vc-vault.record-id-claim:functionalRecordId}") String recordIdClaim,
            @Value("${mosip.certify.vc-vault.phone-claim:phoneNumbers}") String phoneClaim,
            @Value("${mosip.certify.vc-vault.email-claim:email}") String emailClaim,
            @Value("${mosip.certify.data-provider-plugin.id-field-prefix-uri:}") String idPrefix) {
        this.enabled = enabled;
        this.recordIdClaim = recordIdClaim;
        this.phoneClaim = phoneClaim;
        this.emailClaim = emailClaim;
        this.jdbc = new JdbcTemplate(dataSource); // own instance: does not depend on JdbcTemplate auto-configuration
        this.crypto = new VaultCrypto(encryptionKey);
        if (!enabled) {
            return;
        }
        if (idPrefix == null || idPrefix.isBlank()) {
            throw new IllegalStateException(
                    "mosip.certify.vc-vault.enabled=true requires mosip.certify.data-provider-plugin.id-field-prefix-uri "
                            + "to be set (e.g. urn:openg2p:credential:) so the credential gets an id the holder can use, and the "
                            + "credential template must render ${credentialId} as the VC `id`.");
        }
        if (!crypto.enabled() && !allowPlaintext) {
            throw new IllegalStateException(
                    "mosip.certify.vc-vault.encryption-key is required (base64 of 32 bytes). "
                            + "Set mosip.certify.vc-vault.allow-plaintext=true only for local development.");
        }
        if (!crypto.enabled()) {
            log.warn("VC vault is storing credentials and phone numbers in CLEAR TEXT (allow-plaintext=true)");
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    /** New credential id for the vault: a short claim code the holder can type. */
    public String newCredentialId() {
        return VaultUtils.generateClaimCode();
    }

    /**
     * Stores the signed credential. Throws CertifyException when it cannot, so a credential that could not
     * be stored is never handed out (the wallet could not download it later).
     */
    public void store(
            String credentialId,
            VCResult<?> result,
            String configId,
            List<String> credentialTypes,
            JSONObject claims,
            String issuerDid,
            String holderId) {
        Object credential = result.getCredential();
        String vcText;
        Map<String, Object> vcMap = null;
        if (credential instanceof JsonLDObject jsonLd) {
            vcMap = jsonLd.getJsonObject();
            try {
                vcText = MAPPER.writeValueAsString(vcMap);
            } catch (JsonProcessingException e) {
                log.error("Could not serialise credential {} for the vault", credentialId, e);
                throw new CertifyException("VC_VAULT_STORE_FAILED", "Could not serialise the issued credential");
            }
        } else {
            vcText = String.valueOf(credential); // e.g. an SD-JWT string
        }

        String recordId = claims == null ? null : claims.optString(recordIdClaim, null);
        if (recordId == null || recordId.isBlank()) {
            log.warn("Claim '{}' is missing; vault entry {} is keyed on the credential id only", recordIdClaim, credentialId);
            recordId = credentialId;
        }
        String phone = VaultUtils.primaryPhone(claims == null ? null : claims.opt(phoneClaim));
        String email = VaultUtils.primaryEmail(claims == null ? null : claims.opt(emailClaim));
        if (phone == null && email == null) {
            log.warn("Vault entry {} has neither an email nor a phone number; OTP login will not be possible for it",
                    credentialId);
        }
        String types = (credentialTypes == null || credentialTypes.isEmpty()) ? configId : String.join(",", credentialTypes);

        Object[] args = {
            credentialId,
            recordId,
            configId,
            types,
            result.getFormat(),
            crypto.encrypt(vcText, credentialId),
            crypto.enabled(),
            phone == null ? null : crypto.encrypt(phone, credentialId),
            VaultUtils.maskPhone(phone),
            email == null ? null : crypto.encrypt(email, credentialId),
            VaultUtils.maskEmail(email),
            holderId,
            issuerDid,
            OffsetDateTime.now(ZoneOffset.UTC),
            expiry(vcMap)
        };
        try {
            jdbc.update(INSERT_SQL, args, INSERT_TYPES);
        } catch (DataAccessException e) {
            log.error("Could not store credential {} in the vault", credentialId, e);
            throw new CertifyException("VC_VAULT_STORE_FAILED", "Could not store the issued credential in the vault");
        }
        log.info("Stored credential {} in the vault (config={}, encrypted={}, email={}, phone={})",
                credentialId, configId, crypto.enabled(), VaultUtils.maskEmail(email), VaultUtils.maskPhone(phone));
    }

    private static OffsetDateTime expiry(Map<String, Object> vc) {
        if (vc == null) {
            return null;
        }
        Object value = vc.get("expirationDate");
        if (value == null) {
            value = vc.get("validUntil");
        }
        try {
            return value == null ? null : OffsetDateTime.parse(String.valueOf(value));
        } catch (RuntimeException e) {
            return null;
        }
    }
}
