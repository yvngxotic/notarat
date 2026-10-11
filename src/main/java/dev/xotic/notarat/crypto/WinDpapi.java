package dev.xotic.notarat.crypto;

import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public final class WinDpapi {

    public static class DataBlob extends Structure {
        public int cbData;
        public Pointer pbData;

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("cbData", "pbData");
        }
    }

    public interface Crypt32 extends Library {
        Crypt32 INSTANCE = Native.load("crypt32", Crypt32.class);

        boolean CryptUnprotectData(DataBlob pDataIn, Pointer ppszDataDescr, DataBlob pOptionalEntropy, Pointer pvReserved, Pointer pPromptStruct, int dwFlags,DataBlob pDataOut);

        Pointer LocalFree(Pointer hMem);
    }

    public static byte[] unprotect(byte[] blob) {
        if (blob == null || blob.length == 0) return null;
        DataBlob in = new DataBlob();
        in.cbData = blob.length;
        in.pbData = new Memory(blob.length);
        in.pbData.write(0, blob, 0, blob.length);
        in.write();

        DataBlob out = new DataBlob();
        if (!Crypt32.INSTANCE.CryptUnprotectData(in, null, null, null, null, 0, out)) {
            return null;
        }
        out.read();
        byte[] plain = out.pbData.getByteArray(0, out.cbData);
        Crypt32.INSTANCE.LocalFree(out.pbData);
        return plain;
    }

    private WinDpapi() {}
}