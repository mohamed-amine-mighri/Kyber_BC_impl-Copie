package diffieHellmanTests.diffTest.old; /**
 * @author Amine_Mighri
 */

import org.example.diff.Dh;
import org.junit.Test;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class DiffieHellmanTestCombinedExecutionTime {

    @Test
    public void testCombinedExecutionTimes() throws Exception {
        int iterations = 1000;  // Adjust the number of iterations as needed

        long totalCombinedTime = 0;
        long longestCombinedTime = Long.MIN_VALUE;
        long smallestCombinedTime = Long.MAX_VALUE;

        Class<?> diffieHellmanClass = Dh.class;

        for (int i = 0; i < iterations; i++) {
            long combinedStartTime = System.currentTimeMillis();

            // Accessing private methods using reflection
            Method generateKeyPairMethod = diffieHellmanClass.getDeclaredMethod("generateKeyPair");
            generateKeyPairMethod.setAccessible(true);
            KeyPair keyPair = (KeyPair) generateKeyPairMethod.invoke(null);

            Method generateSharedSecretMethod = diffieHellmanClass.getDeclaredMethod("generateSharedSecret", PrivateKey.class, PublicKey.class);
            generateSharedSecretMethod.setAccessible(true);
            byte[] sharedSecret = (byte[]) generateSharedSecretMethod.invoke(null, keyPair.getPrivate(), keyPair.getPublic());

            long combinedEndTime = System.currentTimeMillis();
            long combinedTime = combinedEndTime - combinedStartTime;

            totalCombinedTime += combinedTime;

            longestCombinedTime = Math.max(longestCombinedTime, combinedTime);
            smallestCombinedTime = Math.min(smallestCombinedTime, combinedTime);
        }

        long averageCombinedTime = totalCombinedTime / iterations;

        writeResultsToFile(averageCombinedTime, longestCombinedTime, smallestCombinedTime);
    }

    private void writeResultsToFile(long avgCombinedTime, long maxCombinedTime, long minCombinedTime) throws Exception {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("DH_combined_execution_time_tests"))) {
            writer.write("Average Combined Time: " + avgCombinedTime + " ms\n");
            writer.write("Longest Combined Time: " + maxCombinedTime + " ms\n");
            writer.write("Smallest Combined Time: " + minCombinedTime + " ms\n");
        }
    }
}
