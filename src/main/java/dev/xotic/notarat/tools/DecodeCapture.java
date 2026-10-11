package dev.xotic.notarat.tools;

import dev.xotic.notarat.Security;
import java.nio.file.Files;
import java.nio.file.Path;

public final class DecodeCapture {
    public static void main(String[] args) throws Exception {
        String b64 = Files.readString(Path.of(args[0])).trim();
        b64 = b64.replaceAll("^\\[\\d+/\\d+\\]\\s*", "");
        String plain = Security.decryptPayload(b64);
        System.out.println(plain);
    }
}