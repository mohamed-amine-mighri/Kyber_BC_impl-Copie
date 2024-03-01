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

import static org.junit.Assert.*;

public class DhKeyAgreementExecutionTimeTest {

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testDhExecutionTime() throws Exception {
        int numberOfExecutions = 1000;
        double[] executionTimes = new double[numberOfExecutions];

        for (int i = 0; i < numberOfExecutions; i++) {
            long startTime = System.nanoTime();
            // Warm-up DH
            warmUpDh();
            // Test DH key exchange
            performDhKeyExchange();

            executionTimes[i] = (System.nanoTime() - startTime) / 1_000_000.0;
        }

        writeResultsToFile(executionTimes);
    }
    private void warmUpDh() throws Exception {
        performDhKeyExchange(); // Warm up the key pair generation
    }
    private void performDhKeyExchange() throws Exception {
        KeyPair aliceKeyPair = generateKeyPair();
        KeyPair bobKeyPair = generateKeyPair(((DHPublicKey) aliceKeyPair.getPublic()).getParams());

        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH", "BC");
        aliceKeyAgree.init(aliceKeyPair.getPrivate());

        KeyFactory bobKeyFac = KeyFactory.getInstance("DH", "BC");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bobKeyPair.getPublic().getEncoded());
        PublicKey bobPubKey = bobKeyFac.generatePublic(x509KeySpec);

        aliceKeyAgree.doPhase(bobPubKey, true);
        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();

        // Additional testing considerations
        assertTrue(aliceSharedSecret.length > 0);
        testSharedSecrets(aliceKeyPair, bobKeyPair, aliceSharedSecret);
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
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("DhTestsResults/dh_key_agreement_execution_times.txt"))) {
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
        writer.write("======================================================================================\n\n");
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

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", "BC");
        keyPairGenerator.initialize(1024);  // Reduced key size to 1024 bits
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
//public class DhKeyAgreementExecutionTimeTest {
//
//    @BeforeClass
//    public static void setUp() {
//        // Add Bouncy Castle provider
//        Security.addProvider(new BouncyCastleProvider());
//    }
//
//    @Test
//    public void testDhExecutionTimes() throws Exception {
//        int numberOfExecutions = 1000;
//
//        // Arrays to store execution times
//        double[] executionTimes = new double[numberOfExecutions];
//        System.gc();
//
//        // Warm-up
//        warmUpDh();
//        System.gc();
//
//        // Test
//        testDhExecutionTime(executionTimes);
//        System.gc();
//
//        // Write results to a file
//        writeResultsToFile(executionTimes);
//    }
//
//    private void warmUpDh() throws Exception {
//        KeyPair aliceKeyPair = Dh.generateKeyPair();
//        byte[] alicePubKeyEnc = aliceKeyPair.getPublic().getEncoded();
//        KeyPair bobKeyPair = Dh.generateKeyPair(((DHPublicKey) aliceKeyPair.getPublic()).getParams());
//        byte[] bobPubKeyEnc = bobKeyPair.getPublic().getEncoded();
//
//        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH", "BC");
//        aliceKeyAgree.init(aliceKeyPair.getPrivate());
//        KeyFactory aliceKeyFac = KeyFactory.getInstance("DH", "BC");
//        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
//        PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
//        aliceKeyAgree.doPhase(bobPubKey, true);
//
//        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH", "BC");
//        bobKeyAgree.init(bobKeyPair.getPrivate());
//        KeyFactory bobKeyFac = KeyFactory.getInstance("DH", "BC");
//        x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);
//        PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);
//        bobKeyAgree.doPhase(alicePubKey, true);
//
//        aliceKeyAgree.generateSecret();
//        bobKeyAgree.generateSecret();
//    }
//
//    private void testDhExecutionTime(double[] executionTimes) throws Exception {
//        for (int i = 0; i < executionTimes.length; i++) {
//            long startTime = System.nanoTime();
//            // Perform Diffie-Hellman key agreement
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
//            aliceKeyAgree.generateSecret();
//            bobKeyAgree.generateSecret();
//
//            executionTimes[i] = (System.nanoTime() - startTime) / 1_000_000.0;
//        }
//    }
//
//    private void writeResultsToFile(double[] executionTimes) {
//        try (BufferedWriter writer = new BufferedWriter(new FileWriter("DhTestsResults/dh_key_agreement_execution_times.txt"))) {
//            writeResults(writer, "Diffie-Hellman Key Agreement", executionTimes);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//
//    private void writeResults(BufferedWriter writer, String name, double[] executionTimes) throws IOException {
//        writer.write(name + " Execution Time tests for key agreement: \n");
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
