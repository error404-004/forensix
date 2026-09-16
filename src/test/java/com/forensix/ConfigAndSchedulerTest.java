package com.forensix;

import com.forensix.model.Config;
import com.forensix.service.ScanScheduler;
import com.forensix.util.ConfigLoader;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigAndSchedulerTest {

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("Verify ConfigLoader loads defaults and saves custom settings")
    void testConfigSaveAndLoad() throws IOException {
        Path configFile = tempDir.resolve("test_config.properties");
        ConfigLoader loader = new ConfigLoader(configFile.toString());

        Config config = loader.loadConfig();
        assertNotNull(config);
        assertEquals(5, config.getFailedLoginThreshold());

        // Modify and save
        config.setFailedLoginThreshold(8);
        config.setMonitoredDirectory("C:/custom/path");
        config.setScanIntervalSeconds(120);
        loader.saveConfig(config);

        // Reload
        Config reloaded = loader.loadConfig();
        assertEquals(8, reloaded.getFailedLoginThreshold());
        assertEquals("C:/custom/path", reloaded.getMonitoredDirectory());
        assertEquals(120, reloaded.getScanIntervalSeconds());
    }

    @Test
    @DisplayName("Verify ScanScheduler execution and stop")
    void testSchedulerLifecycle() throws InterruptedException {
        ScanScheduler scheduler = new ScanScheduler();
        assertFalse(scheduler.isRunning());

        AtomicInteger runCount = new AtomicInteger(0);
        CountDownLatch latch = new CountDownLatch(1);

        scheduler.start(1, () -> {
            runCount.incrementAndGet();
            latch.countDown();
        });

        assertTrue(scheduler.isRunning());
        boolean executed = latch.await(3, TimeUnit.SECONDS);
        assertTrue(executed, "Scheduler should trigger task within 3 seconds");
        assertTrue(runCount.get() >= 1);

        scheduler.stop();
        assertFalse(scheduler.isRunning());
    }
}
