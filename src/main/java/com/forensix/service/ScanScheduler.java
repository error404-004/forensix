package com.forensix.service;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Manages periodic background integrity scans via a single daemon ScheduledExecutorService.
 */
public class ScanScheduler {
    private static final Logger LOGGER = Logger.getLogger(ScanScheduler.class.getName());

    private ScheduledExecutorService executor;
    private ScheduledFuture<?> scheduledTask;
    private boolean running = false;

    public synchronized void start(int intervalSeconds, Runnable scanAction) {
        if (running) {
            stop();
        }

        if (intervalSeconds <= 0) {
            intervalSeconds = 60;
        }

        LOGGER.info("Starting background scan scheduler with interval: " + intervalSeconds + " seconds.");
        executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ForensixSchedulerThread");
            t.setDaemon(true);
            return t;
        });

        int finalInterval = intervalSeconds;
        scheduledTask = executor.scheduleAtFixedRate(() -> {
            try {
                LOGGER.info("Periodic scan triggered by scheduler.");
                scanAction.run();
            } catch (Throwable t) {
                LOGGER.log(Level.SEVERE, "Unexpected error in scheduled scan execution", t);
            }
        }, finalInterval, finalInterval, TimeUnit.SECONDS);

        running = true;
    }

    public synchronized void stop() {
        if (!running) return;
        LOGGER.info("Stopping background scan scheduler...");

        if (scheduledTask != null) {
            scheduledTask.cancel(false);
            scheduledTask = null;
        }

        if (executor != null) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(3, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
            executor = null;
        }

        running = false;
        LOGGER.info("Background scan scheduler stopped.");
    }

    public synchronized boolean isRunning() {
        return running;
    }
}
