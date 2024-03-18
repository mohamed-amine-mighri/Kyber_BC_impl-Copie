package DH;

import org.example.kyber.DH;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DiffieHellmanExampleMemoryTest {

    private static final Logger logger = Logger.getLogger(DiffieHellmanExampleMemoryTest.class.getName());

    @BeforeClass
    public static void setUp() {
        // Add Bouncy Castle provider for Diffie-Hellman
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    @Test
    public void testDiffieHellmanMemoryConsumption() {
        int warmUpIterations = 5;
        int numberOfExecutions = 1000;

        try {
            warmUpDiffieHellman(warmUpIterations);

            long[] memoryConsumption = new long[numberOfExecutions];

            for (int i = 0; i < numberOfExecutions; i++) {
                memoryConsumption[i] = runDiffieHellmanTest();
            }

            writeResultsToFile(memoryConsumption);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "An error occurred during Diffie-Hellman memory consumption tests.", e);
        }
    }

    private void warmUpDiffieHellman(int warmUpIterations) {
        logger.info("Warm-up Diffie-Hellman...");
        try {
            for (int i = 0; i < warmUpIterations; i++) {
                runDiffieHellmanTest();
            }
            logger.info("Warm-up completed.");
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error during Diffie-Hellman warm-up.", e);
        }
    }

    private long runDiffieHellmanTest() {
        // Run garbage collection before each measurement
        System.gc();
        long startMemory = getMemoryUsage();

        try {
            // Generate key pairs for Diffie-Hellman
            KeyPair keyPairA = DH.generateKeyPair();
            KeyPair keyPairB = DH.generateKeyPair();

            // Generate shared secrets
            byte[] secretA = DH.generateSharedSecret(keyPairA.getPrivate(), keyPairB.getPublic());
            byte[] secretB = DH.generateSharedSecret(keyPairB.getPrivate(), keyPairA.getPublic());

            // Compare shared secrets
            //DH.compareSharedSecrets(secretA, secretB);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error during Diffie-Hellman test.", e);
        }

        return getMemoryUsage() - startMemory;
    }

    private long getMemoryUsage() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }

    private void writeResultsToFile(long[] memoryConsumption) {
        // Create the directory if it doesn't exist
        File directory = new File("DiffieHellmanTestsResults");
        if (!directory.exists()) {
            directory.mkdirs();
        }

        // Write results to a file
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("DiffieHellmanTestsResults/Memory_Consumption.txt"))) {
            writeResults(writer, "Diffie-Hellman", memoryConsumption);
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error while writing results to file.", e);
        }
    }

    private void writeResults(BufferedWriter writer, String name, long[] memoryConsumption) throws IOException {
        // Convert bytes to megabytes
        double[] memoryConsumptionMB = Arrays.stream(memoryConsumption)
                .mapToDouble(memory -> (double) memory / (1024 * 1024))
                .toArray();

        writer.write(name + " Memory Consumption tests for key pair generation and shared secret generation: \n");
        writer.write("======================================================================================\n");
        writer.write("Largest Memory Consumption: " + findLargest(memoryConsumptionMB) + " megabytes\n");
        writer.write("Smallest Memory Consumption: " + findSmallest(memoryConsumptionMB) + " megabytes\n");
        writer.write("Average Memory Consumption: " + calculateAverage(memoryConsumptionMB) + " megabytes\n");
        writer.write("Standard Deviation: " + calculateStandardDeviation(memoryConsumptionMB) + " megabytes\n");

        writer.write("======================================================================================\n\n");
    }

    private double calculateStandardDeviation(double[] memoryConsumption) {
        double mean = calculateAverage(memoryConsumption);

        double sumSquaredDifferences = Arrays.stream(memoryConsumption)
                .map(memory -> Math.pow(memory - mean, 2))
                .sum();

        return Math.sqrt(sumSquaredDifferences / memoryConsumption.length);
    }

    private double findLargest(double[] memoryConsumption) {
        return Arrays.stream(memoryConsumption).max().orElse(Double.MIN_VALUE);
    }

    private double findSmallest(double[] memoryConsumption) {
        return Arrays.stream(memoryConsumption).min().orElse(Double.MAX_VALUE);
    }

    private double calculateAverage(double[] memoryConsumption) {
        return Arrays.stream(memoryConsumption).average().orElse(0.0);
    }
}
