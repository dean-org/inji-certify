package io.mosip.certify.vault;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM: base64( nonce[12] || ciphertext || tag[16] ) with the credential id bound in as AAD,
 * so a ciphertext copied onto another row does not decrypt. The vc-store service uses the same format.
 */
public final class VaultCrypto {

    private static final int NONCE_LEN = 12;
    private static final int TAG_BITS = 128;

    private final SecretKeySpec key; // null => clear text (only when allow-plaintext=true)
    private final SecureRandom random = new SecureRandom();

    public VaultCrypto(String base64Key) {
        if (base64Key == null || base64Key.isBlank()) {
            this.key = null;
        } else {
            byte[] raw = Base64.getDecoder().decode(base64Key.trim());
            if (raw.length != 32) {
                throw new IllegalArgumentException("mosip.certify.vc-vault.encryption-key must be 32 bytes, base64-encoded");
            }
            this.key = new SecretKeySpec(raw, "AES");
        }
    }

    public boolean enabled() {
        return key != null;
    }

    public String encrypt(String plaintext, String aad) {
        if (key == null) {
            return plaintext;
        }
        try {
            byte[] nonce = new byte[NONCE_LEN];
            random.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
            byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[NONCE_LEN + ct.length];
            System.arraycopy(nonce, 0, out, 0, NONCE_LEN);
            System.arraycopy(ct, 0, out, NONCE_LEN, ct.length);
            return Base64.getEncoder().encodeToString(out);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Vault encryption failed", e);
        }
    }

    /** Needed by tests; production reads happen in the vc-store service. */
    public String decrypt(String payload, String aad) {
        if (key == null) {
            return payload;
        }
        try {
            byte[] blob = Base64.getDecoder().decode(payload);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, blob, 0, NONCE_LEN));
            cipher.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
            return new String(cipher.doFinal(blob, NONCE_LEN, blob.length - NONCE_LEN), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("Could not decrypt vault payload", e);
        }
    }
}
