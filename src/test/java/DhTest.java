/**
 * @author Amine_Mighri
 */

import org.example.diff.Dh;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


public class DhTest {

    @Test
    public void testKeyPairGeneration() throws NoSuchProviderException, NoSuchAlgorithmException {
        long totalTime = 0;
        long longestTime = Long.MIN_VALUE;
        long shortestTime = Long.MAX_VALUE;

        for (int i = 0; i < 1000; i++) {
            long startTime = System.nanoTime();
            Dh.generateKeyPair();
            long endTime = System.nanoTime();

            long duration = endTime - startTime;
            totalTime += duration;

            if (duration > longestTime) {
                longestTime = duration;
            }

            if (duration < shortestTime) {
                shortestTime = duration;
            }
        }

        long averageTime = totalTime / 1000;
        System.out.println("Average Key Pair Generation Time: " + averageTime / 1_000_000.0+ " ms");
        System.out.println("Longest Key Pair Generation Time: " + longestTime / 1_000_000.0+ " ms");
        System.out.println("Shortest Key Pair Generation Time: " + shortestTime / 1_000_000.0+ " ms");

        // Asserting that the average time is less than a certain threshold (optional)
        //assertTrue(averageTime < 1000000, "Average key pair generation time exceeds threshold.");
    }
}
