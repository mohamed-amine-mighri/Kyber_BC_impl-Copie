package DH;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.example.kyber.DH;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Security;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

public class DHMemoryTest {

    private static final DH dhInstance = new DH();

    @BeforeClass
    public static void setUp() {
        // Add Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testDhMemoryConsumption() throws Exception {
        int numberOfExecutions = 1000;
        long[] memoryConsumptions = new long[numberOfExecutions];

        // Warm-up DH
        warmUpDh();

        // Test DH key exchange
        testDhMemoryConsumption(memoryConsumptions);

        // Write results to a file
        writeResultsToFile(memoryConsumptions);
    }

    private void warmUpDh() throws Exception {
        dhInstance.generateKeyPair(); // Warm up the key pair generation
    }

    private void testDhMemoryConsumption(long[] memoryConsumptions) throws Exception {
        Statistics stats = new Statistics(memoryConsumptions);
        System.gc();
        // Run some warm-up iterations without recording memory consumptions
        for (int i = 0; i < 10; i++) {
            performDhKeyExchange(stats);
        }
        System.gc();
        for (int i = 0; i < memoryConsumptions.length; i++) {

            System.gc();
            //long startMem = getUsedMemoryInMegabytes();
            // Perform DH key exchange
            performDhKeyExchange(stats);

            // Record memory consumption
            //long ensMem = getUsedMemoryInMegabytes();
            memoryConsumptions[i] = getUsedMemoryInMegabytes();
            System.out.println("memory used :" + memoryConsumptions[i]);
            // Introduce a small delay between executions to minimize external factors
            //Thread.sleep(10);
        }
    }

    private void performDhKeyExchange(Statistics stats) throws Exception {
        KeyPair aliceKeyPair = dhInstance.generateKeyPair();
        KeyPair bobKeyPair = dhInstance.generateKeyPair();

        byte[] aliceSharedSecret = dhInstance.generateSharedSecret(aliceKeyPair.getPrivate(), bobKeyPair.getPublic());

        // Additional testing considerations
        assertTrue(aliceSharedSecret.length > 0);
        testSharedSecrets(aliceKeyPair, bobKeyPair, aliceSharedSecret);

        // Add the memory consumption to statistics
        stats.addValue(getUsedMemoryInMegabytes());
    }

    private void testSharedSecrets(KeyPair keyPair1, KeyPair keyPair2, byte[] sharedSecret) throws Exception {
        byte[] computedSecret1 = dhInstance.generateSharedSecret(keyPair1.getPrivate(), keyPair2.getPublic());

        // Assert that shared secrets are equal
        assertArrayEquals(sharedSecret, computedSecret1);
    }

    private void writeResultsToFile(long[] memoryConsumptions) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("DhTestsResults/dh_memory_consumptions.txt"))) {
            Statistics stats = new Statistics(memoryConsumptions);
            writeResults(writer, "DH Key Exchange", stats);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void writeResults(BufferedWriter writer, String name, Statistics stats) throws IOException {
        writer.write(name + " Memory Consumption tests for key exchange:\n");
        writer.write("======================================================================================\n");
        writer.write("Highest Memory Consumption: " + stats.getMax() + " MB\n");
        writer.write("Lowest Memory Consumption: " + stats.getMin() + " MB\n");
        writer.write("Average Memory Consumption: " + stats.getMean() + " MB\n");
        writer.write("Standard Deviation: " + stats.getStandardDeviation() + " MB\n");

        writer.write("======================================================================================\n\n");
    }

    static class Statistics {
        private long count = 0;
        private long sum = 0;
        private long min = Long.MAX_VALUE;
        private long max = Long.MIN_VALUE;
        private double sumSquareDiff = 0;

        public Statistics(long[] memoryConsumptions) {
            for (long memory : memoryConsumptions) {
                addValue(memory);
            }
        }

        public void addValue(long value) {
            count++;
            sum += value;
            min = Math.min(min, value);
            max = Math.max(max, value);
            sumSquareDiff += (value - getMean()) * (value - getMean());
        }

        public long getCount() {
            return count;
        }

        public long getSum() {
            return sum;
        }

        public long getMin() {
            return min;
        }

        public long getMax() {
            return max;
        }

        public double getMean() {
            return (double) sum / count;
        }

        public double getStandardDeviation() {
            double variance = sumSquareDiff / count;
            return Math.sqrt(variance);
        }
    }

    private static long getUsedMemoryInMegabytes() {
        Runtime runtime = Runtime.getRuntime();
        long totalMemory = runtime.totalMemory();
        long freeMemory = runtime.freeMemory();
        long usedMemory = totalMemory - freeMemory;

        return usedMemory / (1024 * 1024); // Convert to megabytes
    }
}
