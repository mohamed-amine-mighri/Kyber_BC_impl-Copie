package DH;

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
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.Assert.assertTrue;

public class DHExecutionTimeExampleTest {

    private static final Logger logger = Logger.getLogger(DHExecutionTimeExampleTest.class.getName());

    @BeforeClass
    public static void setUp() {
        // Add Bouncy Castle PQC provider
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    @Test
    public void testDHExecutionTimes() {
        int numberOfExecutions = 1000;
        double[] executionTimes = new double[numberOfExecutions];

        try {
            warmUpDH();

            for (int i = 0; i < numberOfExecutions; i++) {
                long startTime = System.nanoTime();

                performDhKeyExchange();

                executionTimes[i] = (System.nanoTime() - startTime) / 1000000.0;

                System.out.println("Time : "+executionTimes[i]);
            }

            writeResultsToFile(executionTimes);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "An error occurred during DH execution time tests.", e);
        }
    }

    private void warmUpDH() {
        logger.info("Warm-up DH...");
        try {
            for (int j = 0; j < 5; j++) { // Reduced the number of iterations
                performDhKeyExchange(); // Use the same method for warm-up
            }
            logger.info("Warm-up completed.");
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error during DH warm-up.", e);
        }
    }

    private void performDhKeyExchange() throws Exception {
        KeyPair aliceKeyPair = DH.generateKeyPair();
        KeyPair bobKeyPair = DH.generateKeyPair();

        byte[] aliceSharedSecret = DH.generateSharedSecret(aliceKeyPair.getPrivate(), bobKeyPair.getPublic());
        System.out.println("Length DH is : " + aliceSharedSecret.length + " bytes");

        // Additional testing considerations
        assertTrue(aliceSharedSecret.length > 0);
        // Uncomment the following line if necessary
        // testSharedSecrets(aliceKeyPair, bobKeyPair, aliceSharedSecret);
    }

    private void writeResultsToFile(double[] executionTimes) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("DHTestsResults/dh_execution_times.txt"))) {
            writeResults(writer, "DH Key Exchange", executionTimes);
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error while writing results to file.", e);
        }
    }

    // Modify the writeResults method
    private void writeResults(BufferedWriter writer, String name, double[] executionTimes) throws IOException {
        writer.write(name + " Execution Time tests for key pair generation and secret key encapsulation: \n");
        writer.write("======================================================================================\n");
        writer.write("Longest Execution Time: " + findLongest(executionTimes) + " ms\n");
        writer.write("Shortest Execution Time: " + findShortest(executionTimes) + " ms\n");
        writer.write("Average Execution Time: " + calculateAverage(executionTimes) + " ms\n");
        writer.write("Standard Deviation: " + calculateStandardDeviation(executionTimes) + " ms\n");

        Arrays.sort(executionTimes); // Sort the execution times

        int tenthIndex = Math.max(0, executionTimes.length - 20); // Index of the tenth longest time
        double tenthLongest = executionTimes[tenthIndex];

        writer.write("Tenth Longest Execution Time: " + tenthLongest + " ms\n");

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
        return Arrays.stream(times).max().orElse(Double.MIN_VALUE);
    }

    private double findShortest(double[] times) {
        return Arrays.stream(times).min().orElse(Double.MAX_VALUE);
    }

    private double calculateAverage(double[] times) {
        return Arrays.stream(times).average().orElse(0.0);
    }
}
