package DH;

import org.example.kyber.ECDH_BC;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;

public class ECDH_BCTest {

    private static final int NUM_EXECUTIONS = 1000;
    private static final String FILENAME = "execution_times.txt";

    private static long[] executionTimes;

    @BeforeAll
    static void setUp() {
        executionTimes = new long[NUM_EXECUTIONS];
    }

    @Test
    public void testKeyGenerationAndSecretKeyGeneration() {
        for (int i = 0; i < NUM_EXECUTIONS; i++) {
            long startTime = System.nanoTime();

            // Initialize two key pairs
            KeyPair keyPairA = ECDH_BC.generateECKeys();
            KeyPair keyPairB = ECDH_BC.generateECKeys();

            // Create two AES secret keys to encrypt/decrypt the message
            SecretKey secretKeyA = ECDH_BC.generateSharedSecret(keyPairA.getPrivate(), keyPairB.getPublic());
            SecretKey secretKeyB = ECDH_BC.generateSharedSecret(keyPairB.getPrivate(), keyPairA.getPublic());

            long endTime = System.nanoTime();
            long duration = endTime - startTime;
            executionTimes[i] = duration;
            System.out.println("time :"+executionTimes[i]);
        }
    }

    @AfterAll
    static void writeResultsToFile() {
        long totalExecutionTime = 0;
        long longestExecutionTime = Long.MIN_VALUE;
        long secondLongestExecutionTime = Long.MIN_VALUE; // New variable for second longest
        long shortestExecutionTime = Long.MAX_VALUE;

        for (long time : executionTimes) {
            totalExecutionTime += time;
            if (time > longestExecutionTime) {
                secondLongestExecutionTime = longestExecutionTime; // Store the previous longest as second longest
                longestExecutionTime = time;
            } else if (time > secondLongestExecutionTime && time != longestExecutionTime) {
                secondLongestExecutionTime = time; // Update second longest if current time is greater but not equal to the longest
            }
            if (time < shortestExecutionTime) {
                shortestExecutionTime = time;
            }
        }

        double averageExecutionTime = (double) (totalExecutionTime - longestExecutionTime) / NUM_EXECUTIONS;

        try (FileWriter writer = new FileWriter(FILENAME)) {
            writer.write("Average Execution Time: " + averageExecutionTime / 1000000.0 + " ms\n");
            writer.write("Longest Execution Time: " + secondLongestExecutionTime / 1000000.0 + " ms\n");
            writer.write("Shortest Execution Time: " + shortestExecutionTime / 1000000.0 + " ms\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
