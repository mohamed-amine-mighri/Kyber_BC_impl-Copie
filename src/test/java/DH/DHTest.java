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

public class DHTest {

    private static final DH dhInstance = new DH();

    @BeforeClass
    public static void setUp() {
        // Add Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testDhExecutionTime() throws Exception {
        int numberOfExecutions = 1000;
        double[] executionTimes = new double[numberOfExecutions];

        // Warm-up DH
        warmUpDh();

        // Test DH key exchange
        testDhExecutionTime(executionTimes);

        // Write results to a file
        writeResultsToFile(executionTimes);
    }

    private void warmUpDh() throws Exception {
        dhInstance.generateKeyPair(); // Warm up the key pair generation
    }

    private void testDhExecutionTime(double[] executionTimes) throws Exception {
        Statistics stats = new Statistics(executionTimes);

        // Run some warm-up iterations without recording execution times
        for (int i = 0; i < 10; i++) {
            performDhKeyExchange(stats);
        }

        for (int i = 0; i < executionTimes.length; i++) {
            long startTime = System.nanoTime();

            // Perform DH key exchange
            performDhKeyExchange(stats);

            executionTimes[i] = (System.nanoTime() - startTime) / 1_000_000.0;
        }
    }

    private void performDhKeyExchange(Statistics stats) throws Exception {
        KeyPair aliceKeyPair = dhInstance.generateKeyPair();
        KeyPair bobKeyPair = dhInstance.generateKeyPair();

        byte[] aliceSharedSecret = dhInstance.generateSharedSecret(aliceKeyPair.getPrivate(), bobKeyPair.getPublic());

        // Additional testing considerations
        assertTrue(aliceSharedSecret.length > 0);
        testSharedSecrets(aliceKeyPair, bobKeyPair, aliceSharedSecret);

        // Add the execution time to statistics
        stats.addValue((System.nanoTime() - stats.getCurrentStartTime()) / 1_000_000.0);
    }

    private void testSharedSecrets(KeyPair keyPair1, KeyPair keyPair2, byte[] sharedSecret) throws Exception {
        byte[] computedSecret1 = dhInstance.generateSharedSecret(keyPair1.getPrivate(), keyPair2.getPublic());

        // Assert that shared secrets are equal
        assertArrayEquals(sharedSecret, computedSecret1);
    }

    private void writeResultsToFile(double[] executionTimes) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("DhTestsResults/dh_execution_times.txt"))) {
            Statistics stats = new Statistics(executionTimes);
            writeResults(writer, "DH Key Exchange", stats);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void writeResults(BufferedWriter writer, String name, Statistics stats) throws IOException {
        writer.write(name + " Execution Time tests for key exchange:\n");
        writer.write("======================================================================================\n");
        writer.write("Longest Execution Time: " + stats.getMax() + " ms\n");
        writer.write("Shortest Execution Time: " + stats.getMin() + " ms\n");
        writer.write("Average Execution Time: " + stats.getMean() + " ms\n");
        writer.write("Standard Deviation: " + stats.getStandardDeviation() + " ms\n");

        writer.write("======================================================================================\n\n");
    }

    static class Statistics {
        private long count = 0;
        private double sum = 0;
        private double min = Double.MAX_VALUE;
        private double max = Double.MIN_VALUE;
        private double sumSquareDiff = 0;
        private long currentStartTime;

        public Statistics(double[] executionTimes) {
            for (double time : executionTimes) {
                addValue(time);
            }
        }

        public void addValue(double value) {
            count++;
            sum += value;
            min = Math.min(min, value);
            max = Math.max(max, value);
            sumSquareDiff += (value - getMean()) * (value - getMean());
            currentStartTime = System.nanoTime();
        }

        public long getCount() {
            return count;
        }

        public double getSum() {
            return sum;
        }

        public double getMin() {
            return min;
        }

        public double getMax() {
            return max;
        }

        public double getMean() {
            return sum / count;
        }

        public double getStandardDeviation() {
            double variance = sumSquareDiff / count;
            return Math.sqrt(variance);
        }

        public long getCurrentStartTime() {
            return currentStartTime;
        }
    }
}
