package dev.xotic.notarat.dbus;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

public final class Dbus {

    public static int alignOf(String sig) {
        if (sig == null || sig.isEmpty()) return 1;
        switch (sig.charAt(0)) {
            case 'y': case 'g': case 'v': return 1;
            case 'n': case 'q': case 'b': case 'i': case 'u':
            case 's': case 'o': case 'a': case 'h': return 4;
            case 'x': case 't': case 'd': case '(': case '{': return 8;
            default: return 1;
        }
    }

    @FunctionalInterface public interface Fn { void apply(W w); }

    public static final class W {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();
        public int pos() { return out.size(); }
        public void align(int a) { while (out.size() % a != 0) out.write(0); }

        public void y(int v) { out.write(v & 0xff); }
        public void b(boolean v) {
            align(4);
            out.write(v ? 1 : 0); out.write(0); out.write(0); out.write(0);
        }
        public void u(long v) {
            align(4);
            out.write((int)(v & 0xff));
            out.write((int)((v >>> 8) & 0xff));
            out.write((int)((v >>> 16) & 0xff));
            out.write((int)((v >>> 24) & 0xff));
        }
        public void i(int v) { u(v & 0xffffffffL); }
        public void t(long v) {
            align(8);
            for (int k = 0; k < 8; k++) out.write((int)((v >>> (k*8)) & 0xff));
        }
        public void s(String s) {
            byte[] b = s.getBytes(StandardCharsets.UTF_8);
            u(b.length);
            out.write(b, 0, b.length);
            out.write(0);
        }
        public void g(String sig) {
            byte[] b = sig.getBytes(StandardCharsets.US_ASCII);
            y(b.length);
            out.write(b, 0, b.length);
            out.write(0);
        }
        public void o(String p) { s(p); }
        public void v(String sig, Fn body) {
            g(sig);
            align(alignOf(sig));
            body.apply(this);
        }
        public void array(String elementSig, Fn body) {
            align(4);
            int lenPos = out.size();
            out.write(0); out.write(0); out.write(0); out.write(0);
            align(alignOf(elementSig));
            int start = out.size();
            body.apply(this);
            int end = out.size();
            int n = end - start;
            byte[] arr = out.toByteArray();
            arr[lenPos]   = (byte)(n & 0xff);
            arr[lenPos+1] = (byte)((n >>> 8) & 0xff);
            arr[lenPos+2] = (byte)((n >>> 16) & 0xff);
            arr[lenPos+3] = (byte)((n >>> 24) & 0xff);
            out.reset();
            out.write(arr, 0, arr.length);
        }
        public void struct(Fn body) { align(8); body.apply(this); }
        public byte[] bytes() { return out.toByteArray(); }
    }

    public static final class R {
        public final byte[] buf;
        public int pos;
        public R(byte[] buf) { this(buf, 0); }
        public R(byte[] buf, int pos) { this.buf = buf; this.pos = pos; }
        public void align(int a) { while (pos % a != 0) pos++; }
        public int y() {
            if (pos >= buf.length) throw new IllegalStateException("byte overrun at " + pos);
            return buf[pos++] & 0xff;
        }
        public boolean b() { align(4); int v = y(); pos += 3; return v != 0; }
        public long u() {
            align(4);
            long v = (buf[pos] & 0xffL)
                    | ((buf[pos+1] & 0xffL) << 8)
                    | ((buf[pos+2] & 0xffL) << 16)
                    | ((buf[pos+3] & 0xffL) << 24);
            pos += 4;
            return v;
        }
        public int i() { return (int) u(); }
        public long t() {
            align(8);
            long v = 0;
            for (int k = 0; k < 8; k++) v |= (buf[pos+k] & 0xffL) << (k*8);
            pos += 8;
            return v;
        }
        public String s() {
            int len = (int) u();
            if (len < 0 || pos + len > buf.length) {
                throw new IllegalStateException(
                        "string overrun: len=" + len + " pos=" + pos + " cap=" + buf.length);
            }
            String v = new String(buf, pos, len, StandardCharsets.UTF_8);
            pos += len + 1;
            return v;
        }
        public String g() {
            int len = y();
            if (len < 0 || pos + len > buf.length) {
                throw new IllegalStateException(
                        "signature overrun: len=" + len + " pos=" + pos + " cap=" + buf.length);
            }
            String v = new String(buf, pos, len, StandardCharsets.US_ASCII);
            pos += len + 1;
            return v;
        }
        public String o() { return s(); }
        public void skip(String sig) {
            if (sig == null || sig.isEmpty()) return;
            switch (sig.charAt(0)) {
                case 'y': y(); break;
                case 'b': b(); break;
                case 'n': case 'q': case 'i': case 'u': align(4); pos += 4; break;
                case 'x': case 't': case 'd': align(8); pos += 8; break;
                case 's': case 'o': s(); break;
                case 'g': g(); break;
                case 'v': { String inner = g(); skip(inner); break; }
                case 'a': {
                    align(4);
                    int len = (int) u();
                    align(alignOf(sig.substring(1)));
                    pos += len;
                    break;
                }
                default: break;
            }
        }
    }
}