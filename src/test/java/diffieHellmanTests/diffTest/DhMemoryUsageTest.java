package diffieHellmanTests.diffTest;

/**
 * @author Amine_Mighri
 */

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.example.diff.Dh;
import org.junit.Test;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;

public class DhMemoryUsageTest {

    @Test
    public void testDhMemoryUsage() throws Exception {
        // Add Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());

        int warmUpIterations = 5;
        int numberOfExecutions = 1000;

        // Arrays to store memory usage
        double[] memoryUsage = new double[numberOfExecutions];

        // Warm-up DH
        for (int i = 0; i < warmUpIterations; i++) {
            runDhTest();
        }

        // Test DH key exchange
        for (int i = 0; i < numberOfExecutions; i++) {
            memoryUsage[i] = runDhTest();
        }

        // Write results to a file
        writeResultsToFile(memoryUsage);
    }

    private double runDhTest() throws Exception {
        // Run garbage collection before each measurement
        System.gc();
        long startMemory = getMemoryUsage();
        // Perform DH key exchange
        KeyPair aliceKeyPair = Dh.generateKeyPair();
        byte[] alicePubKeyEnc = aliceKeyPair.getPublic().getEncoded();
        KeyPair bobKeyPair = Dh.generateKeyPair(((DHPublicKey) aliceKeyPair.getPublic()).getParams());
        byte[] bobPubKeyEnc = bobKeyPair.getPublic().getEncoded();
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH", "BC");
        aliceKeyAgree.init(aliceKeyPair.getPrivate());
        KeyFactory aliceKeyFac = KeyFactory.getInstance("DH", "BC");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
        PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
        aliceKeyAgree.doPhase(bobPubKey, true);
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH", "BC");
        bobKeyAgree.init(bobKeyPair.getPrivate());
        KeyFactory bobKeyFac = KeyFactory.getInstance("DH", "BC");
        x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);
        PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);
        bobKeyAgree.doPhase(alicePubKey, true);
        // Generate the shared secret
        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
        byte[] bobSharedSecret = bobKeyAgree.generateSecret();
        return (getMemoryUsage() - startMemory) / (1024.0 * 1024.0); // Convert to megabytes
    }

    private long getMemoryUsage() {
        return ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed();
    }

    private void writeResultsToFile(double[] memoryUsage) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("DhTestsResults/dh_memory_usage.txt"))) {
            writer.write("DH Key Exchange Memory Usage tests:\n");
            writer.write("======================================================================================\n");
            writer.write("\n");

            // Writing results
            writer.write("Maximum Memory Usage: " + findMaximum(memoryUsage) + " megabytes\n");
            writer.write("Minimum Memory Usage: " + findMinimum(memoryUsage) + " megabytes\n");
            writer.write("Average Memory Usage: " + calculateAverage(memoryUsage) + " megabytes\n");

            writer.write("======================================================================================\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private double findMaximum(double[] values) {
        double maximum = Double.MIN_VALUE;
        for (double value : values) {
            if (value > maximum) {
                maximum = value;
            }
        }
        return maximum;
    }

    private double findMinimum(double[] values) {
        double minimum = Double.MAX_VALUE;
        for (double value : values) {
            if (value < minimum) {
                minimum = value;
            }
        }
        return minimum;
    }

    private double calculateAverage(double[] values) {
        double sum = 0.0;
        for (double value : values) {
            sum += value;
        }
        return sum / values.length;
    }
}
