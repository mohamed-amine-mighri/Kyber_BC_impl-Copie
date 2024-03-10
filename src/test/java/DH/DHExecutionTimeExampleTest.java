package DH;

/**
 * @author Amine_Mighri
 */

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.example.kyber.DH;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;

import static org.junit.Assert.assertTrue;

public class DHExecutionTimeExampleTest {

    @BeforeClass
    public static void setUp() {
        // Add Bouncy Castle PQC provider
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    @Test
    public void testDHExecutionTimes() throws Exception {
        int numberOfExecutions = 1000;

        // Arrays to store execution times
        double[] executionTimes = new double[numberOfExecutions];

        // Warm-up DH
        warmUpDH();

        // Test DH key exchange
        testDHExecutionTime(executionTimes);

        // Write results to a file
        writeResultsToFile(executionTimes);
    }

    private void warmUpDH() throws Exception {
        System.out.println("Warm-up DH...");
        performDHWarmUp();
        System.out.println("Warm-up completed.");
    }

    private void performDHWarmUp() throws Exception {
        // Warm-up loop
        for (int j = 0; j < 1000; j++) { // Same number of iterations for all DH variations
            KeyPair aliceKeyPair = DH.generateKeyPair();
            KeyPair bobKeyPair = DH.generateKeyPair();

            byte[] aliceSharedSecret = DH.generateSharedSecret(aliceKeyPair.getPrivate(), bobKeyPair.getPublic());

            //assertTrue(aliceSharedSecret.length > 0);
            //testSharedSecrets(aliceKeyPair, bobKeyPair, aliceSharedSecret);
        }
    }

    private void testDHExecutionTime(double[] executionTimes) throws Exception {
        System.out.println("Testing DH...");
        performDHTests(executionTimes);
        System.out.println("Testing completed.");
    }

    private void performDHTests(double[] executionTimes) throws Exception {
        System.gc();
        for (int i = 0; i < executionTimes.length; i++) {
            long startTime = System.nanoTime();

            // Perform DH key exchange
            performDhKeyExchange();

            executionTimes[i] = (System.nanoTime() - startTime) / 1000000.0;
        }
    }

    private void performDhKeyExchange() throws Exception {
        KeyPair aliceKeyPair = DH.generateKeyPair();
        KeyPair bobKeyPair = DH.generateKeyPair();

        byte[] aliceSharedSecret = DH.generateSharedSecret(aliceKeyPair.getPrivate(), bobKeyPair.getPublic());

        // Additional testing considerations
        assertTrue(aliceSharedSecret.length > 0);
        //testSharedSecrets(aliceKeyPair, bobKeyPair, aliceSharedSecret);
    }

    private void writeResultsToFile(double[] executionTimes) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("DHTestsResults/dh_execution_times.txt"))) {
            writeResults(writer, "DH Key Exchange", executionTimes);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void writeResults(BufferedWriter writer, String name, double[] executionTimes) throws IOException {
        writer.write(name + " Execution Time tests for key exchange:\n");
        writer.write("======================================================================================\n");
        writer.write("Longest Execution Time: " + findLongest(executionTimes) + " ms\n");
        writer.write("Shortest Execution Time: " + findShortest(executionTimes) + " ms\n");
        writer.write("Average Execution Time: " + calculateAverage(executionTimes) + " ms\n");
        writer.write("Standard Deviation: " + calculateStandardDeviation(executionTimes) + " ms\n");

        writer.write("======================================================================================\n\n");
    }
    private double calculateStandardDeviation(double[] times) {
        double mean = calculateAverage(times);

        // Start the stream from the second element (index 1)
        double sumSquaredDifferences = Arrays.stream(times, 1, times.length)
                .map(time -> Math.pow(time - mean, 2))
                .sum();

        // Calculate the standard deviation based on the adjusted length
        return Math.sqrt(sumSquaredDifferences / (times.length - 1));
    }
    private double findLongest(double[] times) {
        double longest = Double.MIN_VALUE;
        for (double time : times) {
            if (time > longest) {
                longest = time;
            }
        }
        return longest;
    }

    private double findShortest(double[] times) {
        double shortest = Double.MAX_VALUE;
        for (double time : times) {
            if (time < shortest) {
                shortest = time;
            }
        }
        return shortest;
    }

    private double calculateAverage(double[] times) {
        double sum = 0.0;
        for (double time : times) {
            sum += time;
        }
        return sum / times.length;
    }
}
