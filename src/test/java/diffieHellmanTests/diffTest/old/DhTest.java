package diffieHellmanTests.diffTest.old;

import org.example.diff.Dh;
import org.junit.Test;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class DhTest {

    @Test
    public void testCombinedExecutionTimes() throws Exception {
        int iterations = 1000;  // Adjust the number of iterations as needed

        long totalAliceKeyAgreeTime = 0;
        long longestAliceKeyAgreeTime = Long.MIN_VALUE;
        long smallestAliceKeyAgreeTime = Long.MAX_VALUE;

        long totalBobKeyAgreeTime = 0;
        long longestBobKeyAgreeTime = Long.MIN_VALUE;
        long smallestBobKeyAgreeTime = Long.MAX_VALUE;

        long totalSharedSecretGenTime = 0;
        long longestSharedSecretGenTime = Long.MIN_VALUE;
        long smallestSharedSecretGenTime = Long.MAX_VALUE;

        for (int i = 0; i < iterations; i++) {
            long aliceStartTime = System.currentTimeMillis();
            KeyPair aliceKeyPair = Dh.generateKeyPair();
            byte[] alicePubKeyEnc = aliceKeyPair.getPublic().getEncoded();
            long aliceEndTime = System.currentTimeMillis();
            long aliceKeyPairGenTime = aliceEndTime - aliceStartTime;

            long bobStartTime = System.currentTimeMillis();
            KeyPair bobKeyPair = Dh.generateKeyPair(((DHPublicKey) aliceKeyPair.getPublic()).getParams());
            byte[] bobPubKeyEnc = bobKeyPair.getPublic().getEncoded();
            long bobEndTime = System.currentTimeMillis();
            long bobKeyPairGenTime = bobEndTime - bobStartTime;

            // Alice uses Bob's public key for the key agreement
            long aliceKeyAgreeStartTime = System.currentTimeMillis();
            KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH", "BC");
            aliceKeyAgree.init(aliceKeyPair.getPrivate());
            KeyFactory aliceKeyFac = KeyFactory.getInstance("DH", "BC");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
            PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
            aliceKeyAgree.doPhase(bobPubKey, true);
            long aliceKeyAgreeEndTime = System.currentTimeMillis();
            long aliceKeyAgreeTime = aliceKeyAgreeEndTime - aliceKeyAgreeStartTime;

            // Bob uses Alice's public key for the key agreement
            long bobKeyAgreeStartTime = System.currentTimeMillis();
            KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH", "BC");
            bobKeyAgree.init(bobKeyPair.getPrivate());
            KeyFactory bobKeyFac = KeyFactory.getInstance("DH", "BC");
            x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);
            PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);
            bobKeyAgree.doPhase(alicePubKey, true);
            long bobKeyAgreeEndTime = System.currentTimeMillis();
            long bobKeyAgreeTime = bobKeyAgreeEndTime - bobKeyAgreeStartTime;

            // Generate the shared secret
            long sharedSecretGenStartTime = System.currentTimeMillis();
            byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
            byte[] bobSharedSecret = bobKeyAgree.generateSecret();
            long sharedSecretGenEndTime = System.currentTimeMillis();
            long sharedSecretGenTime = sharedSecretGenEndTime - sharedSecretGenStartTime;

            totalAliceKeyAgreeTime += aliceKeyAgreeTime;
            longestAliceKeyAgreeTime = Math.max(longestAliceKeyAgreeTime, aliceKeyAgreeTime);
            smallestAliceKeyAgreeTime = Math.min(smallestAliceKeyAgreeTime, aliceKeyAgreeTime);

            totalBobKeyAgreeTime += bobKeyAgreeTime;
            longestBobKeyAgreeTime = Math.max(longestBobKeyAgreeTime, bobKeyAgreeTime);
            smallestBobKeyAgreeTime = Math.min(smallestBobKeyAgreeTime, bobKeyAgreeTime);

            totalSharedSecretGenTime += sharedSecretGenTime;
            longestSharedSecretGenTime = Math.max(longestSharedSecretGenTime, sharedSecretGenTime);
            smallestSharedSecretGenTime = Math.min(smallestSharedSecretGenTime, sharedSecretGenTime);
        }

        long avgAliceKeyAgreeTime = totalAliceKeyAgreeTime / iterations;
        long avgBobKeyAgreeTime = totalBobKeyAgreeTime / iterations;
        long avgSharedSecretGenTime = totalSharedSecretGenTime / iterations;

        writeResultsToFile(avgAliceKeyAgreeTime, longestAliceKeyAgreeTime, smallestAliceKeyAgreeTime,
                avgBobKeyAgreeTime, longestBobKeyAgreeTime, smallestBobKeyAgreeTime,
                avgSharedSecretGenTime, longestSharedSecretGenTime, smallestSharedSecretGenTime);
    }

    private void writeResultsToFile(long avgAliceKeyAgreeTime, long maxAliceKeyAgreeTime, long minAliceKeyAgreeTime,
                                    long avgBobKeyAgreeTime, long maxBobKeyAgreeTime, long minBobKeyAgreeTime,
                                    long avgSharedSecretGenTime, long maxSharedSecretGenTime, long minSharedSecretGenTime) throws Exception {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("DiffieHellmanTestsResults/DH_execution_time_tests"))) {
            writer.write("Average Alice Key Agreement Time: " + avgAliceKeyAgreeTime + " ms\n");
            writer.write("Longest Alice Key Agreement Time: " + maxAliceKeyAgreeTime + " ms\n");
            writer.write("Smallest Alice Key Agreement Time: " + minAliceKeyAgreeTime + " ms\n");
            writer.write("\n");
            writer.write("Average Bob Key Agreement Time: " + avgBobKeyAgreeTime + " ms\n");
            writer.write("Longest Bob Key Agreement Time: " + maxBobKeyAgreeTime + " ms\n");
            writer.write("Smallest Bob Key Agreement Time: " + minBobKeyAgreeTime + " ms\n");
            writer.write("\n");
            writer.write("Average Shared Secret Generation Time: " + avgSharedSecretGenTime + " ms\n");
            writer.write("Longest Shared Secret Generation Time: " + maxSharedSecretGenTime + " ms\n");
            writer.write("Smallest Shared Secret Generation Time: " + minSharedSecretGenTime + " ms\n");
        }
    }
}
