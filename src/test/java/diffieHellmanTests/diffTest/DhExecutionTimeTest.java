package diffieHellmanTests.diffTest;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import static org.junit.Assert.*;


public class DhExecutionTimeTest {

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
        generateKeyPair(); // Warm up the key pair generation
    }

    private void testDhExecutionTime(double[] executionTimes) throws Exception {
        KeyPair aliceKeyPair = generateKeyPair();
        KeyPair bobKeyPair = generateKeyPair(((DHPublicKey) aliceKeyPair.getPublic()).getParams());

        // Run some warm-up iterations without recording execution times
        for (int i = 0; i < 10; i++) {
            performDhKeyExchange(aliceKeyPair, bobKeyPair);
        }

        for (int i = 0; i < executionTimes.length; i++) {
            long startTime = System.nanoTime();

            // Perform DH key exchange
            byte[] aliceSharedSecret = performDhKeyExchange(aliceKeyPair, bobKeyPair);

            executionTimes[i] = (System.nanoTime() - startTime) / 1_000_000.0;

            // Additional testing considerations
            assertTrue(executionTimes[i] > 0); // Ensure that execution time is greater than 0
            testSharedSecrets(aliceKeyPair, bobKeyPair, aliceSharedSecret);
        }
    }

    private byte[] performDhKeyExchange(KeyPair aliceKeyPair, KeyPair bobKeyPair) throws Exception {
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH", "BC");
        aliceKeyAgree.init(aliceKeyPair.getPrivate());

        KeyFactory bobKeyFac = KeyFactory.getInstance("DH", "BC");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bobKeyPair.getPublic().getEncoded());
        PublicKey bobPubKey = bobKeyFac.generatePublic(x509KeySpec);

        aliceKeyAgree.doPhase(bobPubKey, true);
        return aliceKeyAgree.generateSecret();
    }

    private void testSharedSecrets(KeyPair keyPair1, KeyPair keyPair2, byte[] sharedSecret) throws Exception {
        KeyAgreement keyAgreement1 = KeyAgreement.getInstance("DH", "BC");
        keyAgreement1.init(keyPair1.getPrivate());

        KeyFactory keyFactory2 = KeyFactory.getInstance("DH", "BC");
        X509EncodedKeySpec x509KeySpec2 = new X509EncodedKeySpec(keyPair2.getPublic().getEncoded());
        PublicKey publicKey2 = keyFactory2.generatePublic(x509KeySpec2);

        keyAgreement1.doPhase(publicKey2, true);
        byte[] computedSecret1 = keyAgreement1.generateSecret();

        // Assert that shared secrets are equal
        assertArrayEquals(sharedSecret, computedSecret1);
    }


    private void writeResultsToFile(double[] executionTimes) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("DhTestsResults/dh_execution_times.txt"))) {
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

        // Start the loop from the second element (index 1)
        for (int i = 1; i < times.length; i++) {
            if (times[i] > longest) {
                longest = times[i];
            }
        }

        return longest;
    }

    private double findShortest(double[] times) {
        double shortest = Double.MAX_VALUE;

        // Start the loop from the second element (index 1)
        for (int i = 1; i < times.length; i++) {
            if (times[i] < shortest) {
                shortest = times[i];
            }
        }

        return shortest;
    }

    private double calculateAverage(double[] times) {
        double sum = 0.0;

        // Start the loop from the second element (index 1)
        for (int i = 1; i < times.length; i++) {
            sum += times[i];
        }

        // Calculate the average based on the reduced length
        return sum / (times.length - 1);
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", "BC");
        keyPairGenerator.initialize(1024);
        return keyPairGenerator.generateKeyPair();
    }

    private KeyPair generateKeyPair(DHParameterSpec params) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", "BC");
        keyPairGenerator.initialize(params);
        return keyPairGenerator.generateKeyPair();
    }
}



//package diffieHellmanTests.diffTest;
//
///**
// * @author Amine_Mighri
// */
//
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.example.diff.Dh;
//import org.junit.BeforeClass;
//import org.junit.Test;
//
//import javax.crypto.KeyAgreement;
//import javax.crypto.interfaces.DHPublicKey;
//import java.io.BufferedWriter;
//import java.io.FileWriter;
//import java.io.IOException;
//import java.security.KeyFactory;
//import java.security.KeyPair;
//import java.security.PublicKey;
//import java.security.Security;
//import java.security.spec.X509EncodedKeySpec;
//
//public class DhExecutionTimeTest {
//
//    @BeforeClass
//    public static void setUp() {
//        // Add Bouncy Castle provider
//        Security.addProvider(new BouncyCastleProvider());
//    }
//
//    @Test
//    public void testDhExecutionTime() throws Exception {
//        int numberOfExecutions = 1000;
//
//        // Array to store execution times
//        double[] executionTimes = new double[numberOfExecutions];
//        System.gc();
//
//        // Warm-up DH
//        warmUpDh();
//        System.gc();
//
//        // Test DH key exchange
//        testDhExecutionTime(executionTimes);
//        System.gc();
//
//        // Write results to a file
//        writeResultsToFile(executionTimes);
//    }
//
//    private void warmUpDh() throws Exception {
//        KeyPair keyPair = Dh.generateKeyPair();
//        byte[] pubKeyEnc = keyPair.getPublic().getEncoded();
//        KeyAgreement keyAgree = KeyAgreement.getInstance("DH", "BC");
//        keyAgree.init(keyPair.getPrivate());
//        KeyFactory keyFac = KeyFactory.getInstance("DH", "BC");
//        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyEnc);
//        PublicKey pubKey = keyFac.generatePublic(x509KeySpec);
//        keyAgree.doPhase(pubKey, true);
//    }
//
//    private void testDhExecutionTime(double[] executionTimes) throws Exception {
//        for (int i = 0; i < executionTimes.length; i++) {
//            long startTime = System.nanoTime();
//
//            // Perform DH key exchange
//            KeyPair aliceKeyPair = Dh.generateKeyPair();
//            byte[] alicePubKeyEnc = aliceKeyPair.getPublic().getEncoded();
//            KeyPair bobKeyPair = Dh.generateKeyPair(((DHPublicKey) aliceKeyPair.getPublic()).getParams());
//            byte[] bobPubKeyEnc = bobKeyPair.getPublic().getEncoded();
//
//            KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH", "BC");
//            aliceKeyAgree.init(aliceKeyPair.getPrivate());
//            KeyFactory aliceKeyFac = KeyFactory.getInstance("DH", "BC");
//            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
//            PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
//            aliceKeyAgree.doPhase(bobPubKey, true);
//
//            KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH", "BC");
//            bobKeyAgree.init(bobKeyPair.getPrivate());
//            KeyFactory bobKeyFac = KeyFactory.getInstance("DH", "BC");
//            x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);
//            PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);
//            bobKeyAgree.doPhase(alicePubKey, true);
//
//            byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
//            byte[] bobSharedSecret = bobKeyAgree.generateSecret();
//
//            executionTimes[i] = (System.nanoTime() - startTime) / 1_000_000.0;
//        }
//    }
//
//    private void writeResultsToFile(double[] executionTimes) {
//        try (BufferedWriter writer = new BufferedWriter(new FileWriter("DhTestsResults/dh_execution_times.txt"))) {
//            writeResults(writer, "DH Key Exchange", executionTimes);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//
//    private void writeResults(BufferedWriter writer, String name, double[] executionTimes) throws IOException {
//        writer.write(name + " Execution Time tests for key exchange:\n");
//        writer.write("======================================================================================\n");
//        writer.write("Longest Execution Time: " + findLongest(executionTimes) + " ms\n");
//        writer.write("Shortest Execution Time: " + findShortest(executionTimes) + " ms\n");
//        writer.write("Average Execution Time: " + calculateAverage(executionTimes) + " ms\n");
//        writer.write("======================================================================================\n\n");
//    }
//
//    private double findLongest(double[] times) {
//        double longest = Double.MIN_VALUE;
//        for (double time : times) {
//            if (time > longest) {
//                longest = time;
//            }
//        }
//        return longest;
//    }
//
//    private double findShortest(double[] times) {
//        double shortest = Double.MAX_VALUE;
//        for (double time : times) {
//            if (time < shortest) {
//                shortest = time;
//            }
//        }
//        return shortest;
//    }
//
//    private double calculateAverage(double[] times) {
//        double sum = 0.0;
//        for (double time : times) {
//            sum += time;
//        }
//        return sum / times.length;
//    }
//}
//
