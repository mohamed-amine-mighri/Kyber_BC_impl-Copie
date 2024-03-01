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


public class DiffieHellmanTest {

    @Test
    public void testExecutionTimes() throws Exception {
        int iterations = 1000;  // Adjust the number of iterations as needed

        long totalKeyPairTime = 0;
        long totalSharedSecretTime = 0;
        long longestKeyPairTime = Long.MIN_VALUE;
        long longestSharedSecretTime = Long.MIN_VALUE;
        long smallestKeyPairTime = Long.MAX_VALUE;
        long smallestSharedSecretTime = Long.MAX_VALUE;

        Class<?> diffieHellmanClass = Dh.class;

        for (int i = 0; i < iterations; i++) {
            long keyPairStartTime = System.currentTimeMillis();

            // Accessing private method generateKeyPair using reflection
            Method generateKeyPairMethod = diffieHellmanClass.getDeclaredMethod("generateKeyPair");
            generateKeyPairMethod.setAccessible(true);
            KeyPair keyPair = (KeyPair) generateKeyPairMethod.invoke(null);

            long keyPairEndTime = System.currentTimeMillis();
            long keyPairTime = keyPairEndTime - keyPairStartTime;

            long sharedSecretStartTime = System.currentTimeMillis();

            // Accessing private method generateSharedSecret using reflection
            Method generateSharedSecretMethod = diffieHellmanClass.getDeclaredMethod("generateSharedSecret", PrivateKey.class, PublicKey.class);
            generateSharedSecretMethod.setAccessible(true);
            byte[] sharedSecret = (byte[]) generateSharedSecretMethod.invoke(null, keyPair.getPrivate(), keyPair.getPublic());

            long sharedSecretEndTime = System.currentTimeMillis();
            long sharedSecretTime = sharedSecretEndTime - sharedSecretStartTime;

            totalKeyPairTime += keyPairTime;
            totalSharedSecretTime += sharedSecretTime;

            longestKeyPairTime = Math.max(longestKeyPairTime, keyPairTime);
            longestSharedSecretTime = Math.max(longestSharedSecretTime, sharedSecretTime);

            smallestKeyPairTime = Math.min(smallestKeyPairTime, keyPairTime);
            smallestSharedSecretTime = Math.min(smallestSharedSecretTime, sharedSecretTime);
        }

        long averageKeyPairTime = totalKeyPairTime / iterations;
        long averageSharedSecretTime = totalSharedSecretTime / iterations;

        writeResultsToFile(averageKeyPairTime, longestKeyPairTime, smallestKeyPairTime,
                averageSharedSecretTime, longestSharedSecretTime, smallestSharedSecretTime);
    }

    private void writeResultsToFile(long avgKeyPairTime, long maxKeyPairTime, long minKeyPairTime,
                                    long avgSharedSecretTime, long maxSharedSecretTime, long minSharedSecretTime) throws Exception {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("DH_execution_time_tests"))) {
            writer.write("Average Key Pair Time: " + avgKeyPairTime + " ms\n");
            writer.write("Longest Key Pair Time: " + maxKeyPairTime + " ms\n");
            writer.write("Smallest Key Pair Time: " + minKeyPairTime + " ms\n");
            writer.write("\n");
            writer.write("Average Shared Secret Time: " + avgSharedSecretTime + " ms\n");
            writer.write("Longest Shared Secret Time: " + maxSharedSecretTime + " ms\n");
            writer.write("Smallest Shared Secret Time: " + minSharedSecretTime + " ms\n");
        }
    }
}
