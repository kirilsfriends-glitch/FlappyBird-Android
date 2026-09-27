package ai.triglyph.core;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM — второй слой каскада.
 *
 * <p>Здесь используется платформенная реализация: на ARMv8 она идёт через
 * инструкции AES/PMULL, то есть в десятки раз быстрее ручной и при этом
 * устойчива к атакам по кэшу (в отличие от табличной реализации на Java).
 */
public final class Aes {

    private Aes() {
    }

    public static byte[] gcmEncrypt(byte[] key, byte[] iv, byte[] plaintext, byte[] aad)
            throws TriglyphException {
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            if (aad != null && aad.length > 0) {
                c.updateAAD(aad);
            }
            return c.doFinal(plaintext);
        } catch (GeneralSecurityException exc) {
            throw new TriglyphException.Crypto("AES-GCM encryption failed: " + exc, exc);
        }
    }

    public static byte[] gcmDecrypt(byte[] key, byte[] iv, byte[] ctAndTag, byte[] aad)
            throws TriglyphException {
        if (ctAndTag.length < 16) {
            throw new TriglyphException.Integrity("ciphertext too short for GCM tag");
        }
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            if (aad != null && aad.length > 0) {
                c.updateAAD(aad);
            }
            return c.doFinal(ctAndTag);
        } catch (javax.crypto.AEADBadTagException exc) {
            throw new TriglyphException.Integrity("AES-GCM: authentication failed");
        } catch (GeneralSecurityException exc) {
            throw new TriglyphException.Crypto("AES-GCM decryption failed: " + exc, exc);
        }
    }
}
