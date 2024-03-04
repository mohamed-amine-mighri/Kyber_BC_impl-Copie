package Kyber;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.example.kyber.KyberExample;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;

public class KyberExecutionTimeExampleTest {

    @BeforeClass
    public static void setUp() {
        // Add Bouncy Castle PQC provider
        Security.addProvider(new BouncyCastlePQCProvider());
    }


    @Test
    public void testKyberExecutionTimes() throws Exception {
        int numberOfExecutions = 1000;

        // Arrays to store execution times
        double[] executionTimes512 = new double[numberOfExecutions];
        double[] executionTimes768 = new double[numberOfExecutions];
        double[] executionTimes1024 = new double[numberOfExecutions];

        // Warm-up Kyber512
        warmUpKyber(KyberParameterSpec.kyber512);

        // Test Kyber512
        testKyberExecutionTime(KyberParameterSpec.kyber512, executionTimes512);

        // Test Kyber768
        testKyberExecutionTime(KyberParameterSpec.kyber768, executionTimes768);

        // Test Kyber1024
        testKyberExecutionTime(KyberParameterSpec.kyber1024, executionTimes1024);

        // Write results to a file
        writeResultsToFile(executionTimes512, executionTimes768, executionTimes1024);
    }

    private void warmUpKyber(KyberParameterSpec kyberParameterSpec) throws Exception {
        System.out.println("Warm-up Kyber512...");
        performKyberWarmUp(kyberParameterSpec);
        System.out.println("Warm-up completed.");
    }

    private void performKyberWarmUp(KyberParameterSpec kyberParameterSpec) throws Exception {
        // Warm-up loop
        for (int i = 0; i < 10; i++) {
            if (kyberParameterSpec.equals(KyberParameterSpec.kyber512)) {
                // Increase the warm-up iterations for Kyber512
                for (int j = 0; j < 50; j++) {
                    warmUpIteration(kyberParameterSpec);
                }
            } else {
                warmUpIteration(kyberParameterSpec);
            }
        }
    }

    private void warmUpIteration(KyberParameterSpec kyberParameterSpec) throws Exception {
        KeyPair senderKeyPair = KyberExample.generateKeyPair(kyberParameterSpec);
        PublicKey senderPublicKey = senderKeyPair.getPublic();

        SecretKeyWithEncapsulation secretKeyWithEncapsulation = KyberExample.generateSecretKeySender(senderPublicKey);
        byte[] encapsulation = secretKeyWithEncapsulation.getEncapsulation();

        KeyPair receiverKeyPair = KyberExample.generateKeyPair(kyberParameterSpec);
        PrivateKey receiverPrivateKey = receiverKeyPair.getPrivate();

        KyberExample.generateSecretKeyReceiver(receiverPrivateKey, encapsulation);
    }

    private void testKyberExecutionTime(KyberParameterSpec kyberParameterSpec, double[] executionTimes) throws Exception {
        System.out.println("Testing Kyber512...");
        performKyberTests(kyberParameterSpec, executionTimes);
        System.out.println("Testing completed.");
    }

    private void performKyberTests(KyberParameterSpec kyberParameterSpec, double[] executionTimes) throws Exception {
        System.gc();
        for (int i = 0; i < executionTimes.length; i++) {
            long startTime = System.nanoTime();

            // Generate key pair and encapsulation
            KeyPair senderKeyPair = KyberExample.generateKeyPair(kyberParameterSpec);
            PublicKey senderPublicKey = senderKeyPair.getPublic();

            SecretKeyWithEncapsulation secretKeyWithEncapsulation = KyberExample.generateSecretKeySender(senderPublicKey);
            byte[] encapsulation = secretKeyWithEncapsulation.getEncapsulation();

            KeyPair receiverKeyPair = KyberExample.generateKeyPair(kyberParameterSpec);
            PrivateKey receiverPrivateKey = receiverKeyPair.getPrivate();

            KyberExample.generateSecretKeyReceiver(receiverPrivateKey, encapsulation);
            executionTimes[i] = (System.nanoTime() - startTime) / 1000000.0;
        }
    }

    private void writeResultsToFile(double[] executionTimes512, double[] executionTimes768, double[] executionTimes1024) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("KyberTestsResults/Full_Process_Of_kyber_keyPair_execution_times.txt"))) {
            writeResults(writer, "Kyber512", executionTimes512);
            writeResults(writer, "Kyber768", executionTimes768);
            writeResults(writer, "Kyber1024", executionTimes1024);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void writeResults(BufferedWriter writer, String name, double[] executionTimes) throws IOException {
        writer.write(name + " Execution Time tests for key pair generation and secret key encapsulation: \n");
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



//package Kyber;
//
//import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
//import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
//import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
//import org.example.kyber.KyberExample;
//import org.junit.BeforeClass;
//import org.junit.Test;
//
//import java.io.BufferedWriter;
//import java.io.FileWriter;
//import java.io.IOException;
//import java.security.KeyPair;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.security.Security;
//import java.util.Arrays;
//
//public class KyberExecutionTimeExampleTest {
//
//    @BeforeClass
//    public static void setUp() {
//        // Add Bouncy Castle PQC provider
//        Security.addProvider(new BouncyCastlePQCProvider());
//    }
//
//    @Test
//    public void testKyberExecutionTimes() throws Exception {
//        int numberOfExecutions = 1000;
//
//        // Arrays to store execution times
//        double[] executionTimes512 = new double[numberOfExecutions];
//        double[] executionTimes768 = new double[numberOfExecutions];
//        double[] executionTimes1024 = new double[numberOfExecutions];
//
//        // Warm-up Kyber512
//        warmUpKyber(KyberParameterSpec.kyber512);
//
//        // Test Kyber512
//        testKyberExecutionTime(KyberParameterSpec.kyber512, executionTimes512);
//
//        // Test Kyber768
//        testKyberExecutionTime(KyberParameterSpec.kyber768, executionTimes768);
//
//        // Test Kyber1024
//        testKyberExecutionTime(KyberParameterSpec.kyber1024, executionTimes1024);
//
//        // Write results to a file
//        writeResultsToFile(executionTimes512, executionTimes768, executionTimes1024);
//    }
//
//    private void warmUpKyber(KyberParameterSpec kyberParameterSpec) throws Exception {
//        System.out.println("Warm-up Kyber512...");
//        performKyberWarmUp(kyberParameterSpec);
//        System.out.println("Warm-up completed.");
//    }
//
//    private void performKyberWarmUp(KyberParameterSpec kyberParameterSpec) throws Exception {
//        // Warm-up loop
//        for (int i = 0; i < 10; i++) {
//            KeyPair senderKeyPair = KyberExample.generateKeyPair(kyberParameterSpec);
//            PublicKey senderPublicKey = senderKeyPair.getPublic();
//
//            SecretKeyWithEncapsulation secretKeyWithEncapsulation = KyberExample.generateSecretKeySender(senderPublicKey);
//            byte[] encapsulation = secretKeyWithEncapsulation.getEncapsulation();
//
//            KeyPair receiverKeyPair = KyberExample.generateKeyPair(kyberParameterSpec);
//            PrivateKey receiverPrivateKey = receiverKeyPair.getPrivate();
//
//            KyberExample.generateSecretKeyReceiver(receiverPrivateKey, encapsulation);
//        }
//    }
//
//    private void testKyberExecutionTime(KyberParameterSpec kyberParameterSpec, double[] executionTimes) throws Exception {
//        System.out.println("Testing Kyber512...");
//        performKyberTests(kyberParameterSpec, executionTimes);
//        System.out.println("Testing completed.");
//    }
//
//    private void performKyberTests(KyberParameterSpec kyberParameterSpec, double[] executionTimes) throws Exception {
//        System.gc();
//        for (int i = 0; i < executionTimes.length; i++) {
//            long startTime = System.nanoTime();
//
//            // Generate key pair and encapsulation
//            KeyPair senderKeyPair = KyberExample.generateKeyPair(kyberParameterSpec);
//            PublicKey senderPublicKey = senderKeyPair.getPublic();
//
//            SecretKeyWithEncapsulation secretKeyWithEncapsulation = KyberExample.generateSecretKeySender(senderPublicKey);
//            byte[] encapsulation = secretKeyWithEncapsulation.getEncapsulation();
//
//            KeyPair receiverKeyPair = KyberExample.generateKeyPair(kyberParameterSpec);
//            PrivateKey receiverPrivateKey = receiverKeyPair.getPrivate();
//
//            KyberExample.generateSecretKeyReceiver(receiverPrivateKey, encapsulation);
//            //assertEquals(receiverPrivateKey, encapsulation);
//            executionTimes[i] = (System.nanoTime() - startTime) / 1000000.0;
//        }
//    }
//
//    private void writeResultsToFile(double[] executionTimes512, double[] executionTimes768, double[] executionTimes1024) {
//        try (BufferedWriter writer = new BufferedWriter(new FileWriter("KyberTestsResults/Full_Process_Of_kyber_keyPair_execution_times.txt"))) {
//            writeResults(writer, "Kyber512", executionTimes512);
//            writeResults(writer, "Kyber768", executionTimes768);
//            writeResults(writer, "Kyber1024", executionTimes1024);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//
//    private void writeResults(BufferedWriter writer, String name, double[] executionTimes) throws IOException {
//        writer.write(name + " Execution Time tests for key pair generation and secret key encapsulation: \n");
//        writer.write("======================================================================================\n");
//        writer.write("Longest Execution Time: " + findLongest(executionTimes) + " ms\n");
//        writer.write("Shortest Execution Time: " + findShortest(executionTimes) + " ms\n");
//        writer.write("Average Execution Time: " + calculateAverage(executionTimes) + " ms\n");
//        writer.write("Standard Deviation: " + calculateStandardDeviation(executionTimes) + " ms\n");
//
//        writer.write("======================================================================================\n\n");
//    }
//
//    private double calculateStandardDeviation(double[] times) {
//        double mean = calculateAverage(times);
//
//        // Start the stream from the second element (index 1)
//        double sumSquaredDifferences = Arrays.stream(times, 1, times.length)
//                .map(time -> Math.pow(time - mean, 2))
//                .sum();
//
//        // Calculate the standard deviation based on the adjusted length
//        return Math.sqrt(sumSquaredDifferences / (times.length - 1));
//    }
//
//    private double findLongest(double[] times) {
//        double longest = Double.MIN_VALUE;
//
//        // Start the loop from the second element (index 1)
//        for (int i = 1; i < times.length; i++) {
//            if (times[i] > longest) {
//                longest = times[i];
//            }
//        }
//
//        return longest;
//    }
//
//    private double findShortest(double[] times) {
//        double shortest = Double.MAX_VALUE;
//
//        // Start the loop from the second element (index 1)
//        for (int i = 1; i < times.length; i++) {
//            if (times[i] < shortest) {
//                shortest = times[i];
//            }
//        }
//
//        return shortest;
//    }
//
//    private double calculateAverage(double[] times) {
//        double sum = 0.0;
//
//        // Start the loop from the second element (index 1)
//        for (int i = 1; i < times.length; i++) {
//            sum += times[i];
//        }
//
//        // Calculate the average based on the sum and the reduced length
//        return sum / (times.length - 1);
//    }
//}
