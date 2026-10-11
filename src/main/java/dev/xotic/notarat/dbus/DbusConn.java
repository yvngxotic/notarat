package dev.xotic.notarat.dbus;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

public final class DbusConn implements AutoCloseable {

    public static final class Reply {
        public int type;
        public int replySerial;
        public String errorName;
        public String signature;
        public byte[] body;
    }

    private final SocketChannel ch;
    private final InputStream in;
    private final OutputStream out;
    private final AtomicInteger serial = new AtomicInteger(1);

    private static final boolean DEBUG = Boolean.getBoolean("notarat.debug");

    public DbusConn() throws Exception {
        String env = System.getProperty("notarat.dbus.address");
        if (env == null || env.isEmpty()) env = System.getenv("DBUS_SESSION_BUS_ADDRESS");
        if (env == null || env.isEmpty()) {
            int uid = uid();
            env = "unix:path=/run/user/" + uid + "/bus";
        }

        String path = null;
        boolean isAbstract = false;
        for (String part : env.split("[;,]")) {
            if (part.startsWith("unix:path="))          path = part.substring(10);
            else if (part.startsWith("path="))          path = part.substring(5);
            else if (part.startsWith("unix:abstract=")) { path = part.substring(14); isAbstract = true; }
            else if (part.startsWith("abstract="))      { path = part.substring(9);  isAbstract = true; }
        }
        if (path == null) throw new IllegalStateException("no unix path in: " + env);

        UnixDomainSocketAddress addr = UnixDomainSocketAddress.of(
                isAbstract ? ("\0" + path) : path);

        this.ch = SocketChannel.open(StandardProtocolFamily.UNIX);
        this.ch.connect(addr);
        this.in  = Channels.newInputStream(ch);
        this.out = Channels.newOutputStream(ch);

        auth();
        hello();
    }

    //sasl

    private void auth() throws Exception {
        out.write(0);
        out.flush();

        String hex = toHex(Integer.toString(uid()));
        out.write(("AUTH EXTERNAL " + hex + "\r\n").getBytes(StandardCharsets.US_ASCII));
        out.flush();

        String line = readLine();
        if (!line.startsWith("OK")) throw new IllegalStateException("auth rejected: " + line);

        out.write("BEGIN\r\n".getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }

    private void hello() throws Exception {
        Reply r = call("org.freedesktop.DBus", "/org/freedesktop/DBus",
                "org.freedesktop.DBus", "Hello", "", w -> {});
        if (r.type != 2) throw new IllegalStateException("Hello: " + r.errorName);
    }

    public Reply call(String dest, String path, String iface, String member,
                      String bodySig, Dbus.Fn bodyWriter) throws Exception {

        int ser;
        synchronized (serial) { ser = serial.getAndIncrement(); }

        Dbus.W w = new Dbus.W();
        w.y('l'); // little-endian
        w.y(1); // METHOD_CALL
        w.y(0);// flags
        w.y(1);// protocol version
        int bodyLenPos = w.pos();
        w.u(0); // body-length placeholder
        w.u(ser);
        w.array("(yv)", hdr -> {
            hdr.struct(f -> { f.y(1); f.v("o", v -> v.o(path)); });
            hdr.struct(f -> { f.y(2); f.v("s", v -> v.s(iface)); });
            hdr.struct(f -> { f.y(3); f.v("s", v -> v.s(member)); });
            if (dest != null)
                hdr.struct(f -> { f.y(6); f.v("s", v -> v.s(dest)); });
            if (bodySig != null && !bodySig.isEmpty())
                hdr.struct(f -> { f.y(8); f.v("g", v -> v.g(bodySig)); });
        });
        w.align(8);
        int bodyStart = w.pos();
        if (bodySig != null && !bodySig.isEmpty()) bodyWriter.apply(w);
        int bodyEnd = w.pos();
        int bodyLen = bodyEnd - bodyStart;

        byte[] bytes = w.bytes();
        bytes[bodyLenPos]   = (byte)(bodyLen & 0xff);
        bytes[bodyLenPos+1] = (byte)((bodyLen >>> 8) & 0xff);
        bytes[bodyLenPos+2] = (byte)((bodyLen >>> 16) & 0xff);
        bytes[bodyLenPos+3] = (byte)((bodyLen >>> 24) & 0xff);

        synchronized (out) { out.write(bytes); out.flush(); }

        while (true) {
            Reply r = readMessage();
            if (r == null) throw new IllegalStateException("connection closed");
            if ((r.type == 2 || r.type == 3) && r.replySerial == ser) return r;
            if (DEBUG && r.type == 4) System.err.println("[Dbus] signal ignored");
        }
    }

    private Reply readMessage() throws Exception {
        byte[] head = readN(16);
        if (head == null) return null;

        int type = head[1] & 0xff;
        long bodyLen         = leU32(head, 4);
        long headerFieldsLen = leU32(head, 12);

        byte[] hdr = readN((int) headerFieldsLen);
        if (hdr == null) return null;

        long cur = 16L + headerFieldsLen;
        int pad = (int)((8 - (cur % 8)) % 8);
        if (pad > 0) readN(pad);
        byte[] body = bodyLen == 0 ? new byte[0] : readN((int) bodyLen);
        if (body == null) return null;

        Reply r = new Reply();
        r.type = type;
        r.body = body;
        r.signature = "";

        Dbus.R rd = new Dbus.R(hdr, 0);
        int end = hdr.length;
        while (rd.pos < end) {
            rd.align(8);
            if (rd.pos >= end) break;
            int code = rd.y();
            String sig = rd.g();
            switch (code) {
                case 4: rd.align(4); r.errorName = rd.s(); break;
                case 5: rd.align(4); r.replySerial = (int) rd.u(); break;
                case 8: rd.align(1); r.signature = rd.g(); break;
                default: rd.skip(sig);
            }
        }
        return r;
    }

    // IO helpers (>_<)

    private String readLine() throws Exception {
        StringBuilder sb = new StringBuilder();
        while (true) {
            int c = in.read();
            if (c < 0) throw new IllegalStateException("auth EOF");
            if (c == '\n') break;
            if (c == '\r') continue;
            sb.append((char) c);
        }
        return sb.toString();
    }

    private byte[] readN(int n) throws Exception {
        byte[] out = new byte[n];
        int got = 0;
        while (got < n) {
            int r = in.read(out, got, n - got);
            if (r < 0) return null;
            got += r;
        }
        return out;
    }

    public static int uid() {
        try (BufferedReader r = new BufferedReader(new FileReader("/proc/self/status"))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("Uid:"))
                    return Integer.parseInt(line.substring(4).trim().split("\\s+")[0]);
            }
        } catch (Exception ignored) {}
        return 1000;
    }

    private static String toHex(String s) {
        StringBuilder sb = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.US_ASCII))
            sb.append(String.format("%02X", b & 0xff));
        return sb.toString();
    }

    private static long leU32(byte[] b, int off) {
        return (b[off] & 0xffL) | ((b[off+1] & 0xffL) << 8)
                | ((b[off+2] & 0xffL) << 16) | ((b[off+3] & 0xffL) << 24);
    }

    @Override public void close() {
        try { ch.close(); } catch (Exception ignored) {}
    }
}