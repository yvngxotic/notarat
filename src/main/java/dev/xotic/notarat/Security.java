package dev.xotic.notarat;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public final class Security {

    private static final String PASSPHRASE = "notarat::CHANGE_ME";
    private static final int NONCE = 12;
    private static final int TAG_BITS = 128;

    private static final SecureRandom RNG = new SecureRandom();

    public static String encryptPayload(String plain) throws Exception {
        byte[] nonce = new byte[NONCE];
        RNG.nextBytes(nonce);

        byte[] key = deriveKey(nonce);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_BITS, nonce));
        byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));

        byte[] out = new byte[nonce.length + ct.length];
        System.arraycopy(nonce, 0, out, 0, nonce.length);
        System.arraycopy(ct, 0, out, nonce.length, ct.length);
        return Base64.getEncoder().encodeToString(out);
    }

    public static String decryptPayload(String b64) throws Exception {
        byte[] all = Base64.getDecoder().decode(b64);
        byte[] nonce = new byte[NONCE];
        System.arraycopy(all, 0, nonce, 0, NONCE);
        byte[] ct = new byte[all.length - NONCE];
        System.arraycopy(all, NONCE, ct, 0, ct.length);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(deriveKey(nonce), "AES"),
                new GCMParameterSpec(TAG_BITS, nonce));
        return new String(c.doFinal(ct), StandardCharsets.UTF_8);
    }

    private static byte[] deriveKey(byte[] nonce) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(PASSPHRASE.getBytes(StandardCharsets.UTF_8));
        md.update(nonce);
        return md.digest();
    }

    private Security() {}
}