package dev.xotic.notarat.dbus;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class SecretService implements AutoCloseable {

    private static final String SVC   = "org.freedesktop.secrets";
    private static final String PATH  = "/org/freedesktop/secrets";
    private static final String IFACE = "org.freedesktop.Secret.Service";
    private static final String ITEM  = "org.freedesktop.Secret.Item";

    private static final boolean DEBUG = Boolean.getBoolean("notarat.debug");

    private final DbusConn conn;
    private String session;

    public SecretService() throws Exception {
        this.conn = new DbusConn();
        openSession();
    }

    private void openSession() throws Exception {
        DbusConn.Reply r = conn.call(SVC, PATH, IFACE, "OpenSession", "sv", w -> {
            w.s("plain");
            w.v("s", v -> v.s(""));
        });
        if (r.type != 2) throw new IllegalStateException("OpenSession: " + r.errorName);

        Dbus.R rd = new Dbus.R(r.body, 0);
        String vsig = rd.g();
        rd.skip(vsig);
        session = rd.o();
    }

    public List<String> search(String schema) throws Exception {
        DbusConn.Reply r = conn.call(SVC, PATH, IFACE, "SearchItems", "a{ss}", w -> {
            w.array("{ss}", arr -> arr.struct(dict -> {
                dict.s("xdg:schema");
                dict.s(schema);
            }));
        });
        List<String> out = new ArrayList<>();
        if (r.type != 2) {
            return out;
        }

        Dbus.R rd = new Dbus.R(r.body, 0);
        rd.align(8);
        for (int k = 0; k < 2; k++) {
            rd.align(4);
            int len = (int) rd.u();
            rd.align(4);
            int end = rd.pos + len;
            while (rd.pos < end) out.add(rd.o());
        }
        return out;
    }

    public String getSecret(String itemPath) throws Exception {
        DbusConn.Reply r = conn.call(SVC, itemPath, ITEM, "GetSecret", "o",
                w -> w.o(session));
        if (r.type != 2) {
            return null;
        }
        Dbus.R rd = new Dbus.R(r.body, 0);
        rd.o();
        rd.align(4);
        int pLen = (int) rd.u();
        rd.pos += pLen;
        rd.align(4);
        int vLen = (int) rd.u();
        byte[] v = new byte[vLen];
        System.arraycopy(rd.buf, rd.pos, v, 0, vLen);
        return new String(v, StandardCharsets.UTF_8);
    }

    @Override public void close() {
        try { conn.close(); } catch (Exception ignored) {}
    }
}