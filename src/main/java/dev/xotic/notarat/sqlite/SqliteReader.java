package dev.xotic.notarat.sqlite;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class SqliteReader {

    private static final String MAGIC = "SQLite format 3\u0000";

    private final byte[] data;
    private final int pageSize;
    private final int usableSize;

    public SqliteReader(byte[] data) {
        if (data == null || data.length < 100) {
            throw new IllegalArgumentException("not a sqlite file");
        }
        String magic = new String(data, 0, 16, StandardCharsets.ISO_8859_1);
        if (!MAGIC.equals(magic)) {
            throw new IllegalArgumentException("bad sqlite magic");
        }
        int ps = ((data[16] & 0xff) << 8) | (data[17] & 0xff);
        this.pageSize = (ps == 1) ? 65536 : ps;
        int reserved = data[20] & 0xff;
        this.usableSize = pageSize - reserved;
        this.data = data;
    }
    public int rootPageOf(String tableName) {
        for (Object[] row : walk(1)) {
            if (row.length < 4) continue;
            if ("table".equals(row[0])
                    && tableName.equals(row[1])
                    && row[3] instanceof Long) {
                return ((Long) row[3]).intValue();
            }
        }
        return -1;
    }

    public List<Object[]> walk(int rootPage) {
        List<Object[]> out = new ArrayList<>();
        walkPage(rootPage, out, 0);
        return out;
    }
    private void walkPage(int pageNum, List<Object[]> out, int depth) {
        if (depth > 64 || pageNum < 1) return;
        int off = pageOffset(pageNum);
        if (off < 0 || off + 12 > data.length) return;

        int type = data[off] & 0xff;
        boolean leaf     = (type == 0x0D);
        boolean interior = (type == 0x05);
        if (!leaf && !interior) return;

        int nCells = u16(off + 3);
        int ptrArray = off + (leaf ? 8 : 12);
        int cellBase = (pageNum == 1) ? 0 : off;

        for (int i = 0; i < nCells; i++) {
            int pOff = ptrArray + i * 2;
            if (pOff + 2 > data.length) break;
            int rel = u16(pOff);
            int cell = cellBase + rel;
            if (cell <= 0 || cell >= data.length) continue;

            if (interior) {
                walkPage((int) u32(cell), out, depth + 1);
            } else {
                Object[] row = readLeafCell(cell);
                if (row != null) out.add(row);
            }
        }

        if (interior) {
            walkPage((int) u32(off + 8), out, depth + 1);
        }
    }
    private Object[] readLeafCell(int cell) {
        Varint payloadLen = varintAt(cell);
        if (payloadLen.next >= data.length) return null;

        Varint rowid = varintAt(payloadLen.next);
        if (rowid.next > data.length) return null;

        int total = (int) payloadLen.value;
        if (total <= 0 || total > 64 * 1024 * 1024) return null;

        byte[] payload = readPayload(rowid.next, total);
        if (payload == null) return null;
        return parseRecord(payload);
    }

    private byte[] readPayload(int start, int total) {
        int U = usableSize;
        int X = U - 35;
        int local;
        if (total <= X) {
            local = total;
        } else {
            int M = ((U - 12) * 32 / 255) - 23;
            int K = M + ((total - M) % (U - 4));
            local = (K <= X) ? K : M;
        }
        if (local > total) local = total;
        if (start < 0 || start + local > data.length) return null;

        if (local == total) {
            return Arrays.copyOfRange(data, start, start + total);
        }
        if (local < 4) return null;

        byte[] out = new byte[total];
        System.arraycopy(data, start, out, 0, local);
        int written = local;
        int nextPage = (int) u32(start + local - 4);

        while (written < total && nextPage > 0 && nextPage < 0x7FFFFFFF) {
            int off = pageOffset(nextPage);
            if (off < 0 || off + usableSize > data.length) break;
            int chunk = Math.min(usableSize - 4, total - written);
            if (chunk <= 0) break;
            System.arraycopy(data, off, out, written, chunk);
            written += chunk;
            nextPage = (int) u32(off + usableSize - 4);
        }
        return out;
    }
    private Object[] parseRecord(byte[] payload) {
        Varint headerSize = varintAt(payload, 0);
        int hdrEnd = (int) headerSize.value;
        if (hdrEnd <= 0 || hdrEnd > payload.length) return null;

        List<Integer> types = new ArrayList<>();
        int pos = headerSize.next;
        while (pos < hdrEnd) {
            Varint t = varintAt(payload, pos);
            types.add((int) t.value);
            pos = t.next;
        }

        Object[] values = new Object[types.size()];
        int body = hdrEnd;
        for (int i = 0; i < types.size(); i++) {
            int t   = types.get(i);
            int len = serialLen(t);
            if (body + len > payload.length) {
                values[i] = null;
                body += len;
                continue;
            }
            values[i] = decode(payload, body, t);
            body += len;
        }
        return values;
    }

    private static int serialLen(int t) {
        switch (t) {
            case 0:  return 0;
            case 1:  return 1;
            case 2:  return 2;
            case 3:  return 3;
            case 4:  return 4;
            case 5:  return 6;
            case 6:  return 8;
            case 7:  return 8;
            case 8:  return 0;
            case 9:  return 0;
            case 10: return 0;
            case 11: return 0;
            default:
                if ((t & 1) == 0) return (t - 12) / 2;
                return (t - 13) / 2;
        }
    }

    private static Object decode(byte[] p, int off, int t) {
        if (t == 0) return null;
        if (t == 8) return 0L;
        if (t == 9) return 1L;

        switch (t) {
            case 1: return (long) p[off];
            case 2: return (long) (short) (((p[off] & 0xff) << 8) | (p[off + 1] & 0xff));
            case 3: {
                int v = ((p[off] & 0xff) << 16) | ((p[off + 1] & 0xff) << 8) | (p[off + 2] & 0xff);
                if ((v & 0x800000) != 0) v |= 0xFF000000;
                return (long) v;
            }
            case 4: {
                long v = ((p[off] & 0xffL) << 24) | ((p[off + 1] & 0xffL) << 16)
                        | ((p[off + 2] & 0xffL) << 8)  |  (p[off + 3] & 0xffL);
                return (int) v;
            }
            case 5: {
                long v = 0;
                for (int i = 0; i < 6; i++) v = (v << 8) | (p[off + i] & 0xffL);
                if ((v & 0x800000000000L) != 0) v |= 0xFFFF000000000000L;
                return v;
            }
            case 6: {
                long v = 0;
                for (int i = 0; i < 8; i++) v = (v << 8) | (p[off + i] & 0xffL);
                return v;
            }
            case 7: {
                long bits = 0;
                for (int i = 0; i < 8; i++) bits = (bits << 8) | (p[off + i] & 0xffL);
                return Double.longBitsToDouble(bits);
            }
            default:
                if ((t & 1) == 0) {
                    int len = (t - 12) / 2;
                    return Arrays.copyOfRange(p, off, off + len);
                }
                int len = (t - 13) / 2;
                return new String(p, off, len, StandardCharsets.UTF_8);
        }
    }
    private static final class Varint {
        final long value;
        final int  next;
        Varint(long value, int next) { this.value = value; this.next = next; }
    }

    private Varint varintAt(int pos) { return varintAt(data, pos); }

    private static Varint varintAt(byte[] p, int pos) {
        if (pos < 0 || pos >= p.length) return new Varint(0, p.length);
        long result = 0;
        for (int i = 0; i < 8; i++) {
            if (pos + i >= p.length) return new Varint(result, p.length);
            byte b = p[pos + i];
            result = (result << 7) | (b & 0x7f);
            if ((b & 0x80) == 0) return new Varint(result, pos + i + 1);
        }
        if (pos + 8 >= p.length) return new Varint(result, p.length);
        result = (result << 8) | (p[pos + 8] & 0xff);
        return new Varint(result, pos + 9);
    }
    private int pageOffset(int pageNum) {
        if (pageNum < 1) return -1;
        if (pageNum == 1) return 100;
        long off = (long) (pageNum - 1) * pageSize;
        if (off >= data.length) return -1;
        return (int) off;
    }

    private int u16(int off) {
        if (off + 2 > data.length) return 0;
        return ((data[off] & 0xff) << 8) | (data[off + 1] & 0xff);
    }

    private long u32(int off) {
        if (off + 4 > data.length) return 0;
        return ((data[off] & 0xffL) << 24) | ((data[off + 1] & 0xffL) << 16)
                | ((data[off + 2] & 0xffL) << 8)  |  (data[off + 3] & 0xffL);
    }
}