package DH;

import org.example.kyber.ECDH_BC;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ECDH_BCMemoryTest {

    private static final int NUM_EXECUTIONS = 1000;
    private static final String FILENAME = "memory_usage.txt";

    private static ArrayList<Long> memoryUsages = new ArrayList<>();

    @BeforeAll
    static void setUp() {
        // Disable verbose GC logging to prevent interference with measurements
        System.setProperty("java.util.logging.config.file", "/dev/null");
    }

    @Test
    public void benchmarkMemoryUsage() {
        for (int i = 0; i < NUM_EXECUTIONS; i++) {
            // Perform the operation for which memory usage is being benchmarked
            measureMemoryUsage();
        }
    }

    private void measureMemoryUsage() {
        // Perform garbage collection before taking measurements to ensure consistency
        System.gc();

        // Allow some time for garbage collection to complete
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // Get memory usage after garbage collection
        long beforeMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();

        // Initialize two key pairs
        KeyPair keyPairA = ECDH_BC.generateECKeys();
        KeyPair keyPairB = ECDH_BC.generateECKeys();

        // Create two AES secret keys to encrypt/decrypt the message
        SecretKey secretKeyA = ECDH_BC.generateSharedSecret(keyPairA.getPrivate(), keyPairB.getPublic());
        SecretKey secretKeyB = ECDH_BC.generateSharedSecret(keyPairB.getPrivate(), keyPairA.getPublic());

        // Get memory usage after creating objects
        long afterMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        long memoryUsage = afterMemory - beforeMemory;

        // Record memory usage
        memoryUsages.add(memoryUsage);
    }

    @AfterAll
    static void writeResultsToFile() {
        long totalMemoryUsage = 0;
        List<Long> sortedMemoryUsages = new ArrayList<>(memoryUsages);
        Collections.sort(sortedMemoryUsages);

        // Get the second highest memory usage
        long secondHighestMemoryUsage = sortedMemoryUsages.get(sortedMemoryUsages.size() - 2);

        for (long memoryUsage : memoryUsages) {
            totalMemoryUsage += memoryUsage;
        }

        double averageMemoryUsage = (double) totalMemoryUsage / NUM_EXECUTIONS;

        try (FileWriter writer = new FileWriter(FILENAME)) {
            writer.write("Average Memory Usage: " + averageMemoryUsage / (1024.0 * 1024.0) + " MB\n");
            writer.write("Second Highest Memory Usage: " + secondHighestMemoryUsage / (1024.0 * 1024.0) + " MB\n");
            writer.write("Lowest Memory Usage: " + sortedMemoryUsages.get(0) / (1024.0 * 1024.0) + " MB\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
