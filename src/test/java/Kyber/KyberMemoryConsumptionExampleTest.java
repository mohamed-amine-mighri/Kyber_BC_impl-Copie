package Kyber;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

public class KyberMemoryConsumptionExampleTest {

    @BeforeClass
    public static void initBouncyCastleProviders() {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }


    @Test
    public void testKyberMemoryUsage() throws Exception {
        int warmUpIterations = 5;
        int numberOfExecutions512 = 1000;
        int numberOfExecutions768 = 1000;
        int numberOfExecutions1024 = 1000;

        // Warm-up Kyber512
        for (int i = 0; i < warmUpIterations; i++) {
            runKyberTest(KyberParameterSpec.kyber512);
        }

        // Arrays to store memory usage
        double[] memoryUsage512 = new double[numberOfExecutions512];
        double[] memoryUsage768 = new double[numberOfExecutions768];
        double[] memoryUsage1024 = new double[numberOfExecutions1024];

        // Test Kyber512
        for (int i = 0; i < numberOfExecutions512; i++) {
            memoryUsage512[i] = runKyberTest(KyberParameterSpec.kyber512);
        }

        // Test Kyber768
        for (int i = 0; i < numberOfExecutions768; i++) {
            memoryUsage768[i] = runKyberTest(KyberParameterSpec.kyber768);
        }

        // Test Kyber1024
        for (int i = 0; i < numberOfExecutions1024; i++) {
            memoryUsage1024[i] = runKyberTest(KyberParameterSpec.kyber1024);
        }

        // Write results to a file
        // Write results to a file
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("KyberTestsResults/kyber_memory_usage.txt"))) {
            writer.write("Kyber memory usage tests for key pair generation and secret key encapsulation: \n");
            writer.write("======================================================================================\n");
            writer.write("\n");

            // Writing Kyber512 results
            writer.write(String.format("Kyber512: Maximum Memory Usage: %.2f megabytes\n", findMaximum(memoryUsage512)));
            writer.write(String.format("Kyber512: Minimum Memory Usage: %.2f megabytes\n", findMinimum(memoryUsage512)));
            writer.write(String.format("Kyber512: Average Memory Usage: %.2f megabytes\n", calculateAverage(memoryUsage512)));
            writer.write("======================================================================================\n");

            // Writing Kyber768 results
            writer.write(String.format("Kyber768: Maximum Memory Usage: %.2f megabytes\n", findMaximum(memoryUsage768)));
            writer.write(String.format("Kyber768: Minimum Memory Usage: %.2f megabytes\n", findMinimum(memoryUsage768)));
            writer.write(String.format("Kyber768: Average Memory Usage: %.2f megabytes\n", calculateAverage(memoryUsage768)));
            writer.write("======================================================================================\n");

            // Writing Kyber1024 results
            writer.write(String.format("Kyber1024: Maximum Memory Usage: %.2f megabytes\n", findMaximum(memoryUsage1024)));
            writer.write(String.format("Kyber1024: Minimum Memory Usage: %.2f megabytes\n", findMinimum(memoryUsage1024)));
            writer.write(String.format("Kyber1024: Average Memory Usage: %.2f megabytes\n", calculateAverage(memoryUsage1024)));
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private double runKyberTest(KyberParameterSpec kyberParameterSpec) throws Exception {
        // Run garbage collection before each measurement
        System.gc();
        long startMemory = getMemoryUsage();
        // Generate key pair and encapsulation for Kyber
        KeyPair keyPair = KyberExample.generateKeyPair(kyberParameterSpec);
        PublicKey publicKey = keyPair.getPublic();
        SecretKeyWithEncapsulation secretKeyWithEncapsulation = KyberExample.generateSecretKeySender(publicKey);
        byte[] encapsulation = secretKeyWithEncapsulation.getEncapsulation();
        KeyPair receiverKeyPair = KyberExample.generateKeyPair(kyberParameterSpec);
        PrivateKey receiverPrivateKey = receiverKeyPair.getPrivate();
        KyberExample.generateSecretKeyReceiver(receiverPrivateKey, encapsulation);
        return (getMemoryUsage() - startMemory) / (1024.0 * 1024.0); // Convert to megabytes
    }

    private long getMemoryUsage() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
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


//import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
//public class Kyber.KyberMemoryConsumptionExampleTest {
//
//    @BeforeClass
//    public static void setUp() {
//        // Add Bouncy Castle PQC provider
//        Security.addProvider(new BouncyCastleProvider());
//        Security.addProvider(new BouncyCastlePQCProvider());
//    }
//
//    @Test
//    public void testKyberMemoryConsumption() throws Exception {
//        int warmUpIterations = 5;
//        int numberOfExecutions512 = 1000;
//        int numberOfExecutions768 = 1000;
//        int numberOfExecutions1024 = 1000;
//
//        // Warm-up Kyber512
//        for (int i = 0; i < warmUpIterations; i++) {
//            runKyberTest(KyberParameterSpec.kyber512);
//        }
//
//        // Arrays to store memory consumption
//        long[] memoryConsumption512 = new long[numberOfExecutions512];
//        long[] memoryConsumption768 = new long[numberOfExecutions768];
//        long[] memoryConsumption1024 = new long[numberOfExecutions1024];
//
//        // Test Kyber512
//        for (int i = 0; i < numberOfExecutions512; i++) {
//            memoryConsumption512[i] = runKyberTest(KyberParameterSpec.kyber512);
//        }
//
//        // Test Kyber768
//        for (int i = 0; i < numberOfExecutions768; i++) {
//            memoryConsumption768[i] = runKyberTest(KyberParameterSpec.kyber768);
//        }
//
//        // Test Kyber1024
//        for (int i = 0; i < numberOfExecutions1024; i++) {
//            memoryConsumption1024[i] = runKyberTest(KyberParameterSpec.kyber1024);
//        }
//
//        // Write results to a file
//        writeResultsToFile(memoryConsumption512, memoryConsumption768, memoryConsumption1024);
//    }
//
//    private long runKyberTest(KyberParameterSpec kyberParameterSpec) throws Exception {
//        // Run garbage collection before each measurement
//        System.gc();
//        long startMemory = getMemoryUsage();
//        // Generate key pair and encapsulation for Kyber
//        KeyPair keyPair = KyberExample.generateKeyPair(kyberParameterSpec);
//        PublicKey publicKey = keyPair.getPublic();
//        SecretKeyWithEncapsulation secretKeyWithEncapsulation = KyberExample.generateSecretKeySender(publicKey);
//        byte[] encapsulation = secretKeyWithEncapsulation.getEncapsulation();
//        KeyPair receiverKeyPair = KyberExample.generateKeyPair(kyberParameterSpec);
//        PrivateKey receiverPrivateKey = receiverKeyPair.getPrivate();
//        KyberExample.generateSecretKeyReceiver(receiverPrivateKey, encapsulation);
//        return getMemoryUsage() - startMemory;
//    }
//
//    private long getMemoryUsage() {
//        Runtime runtime = Runtime.getRuntime();
//        return runtime.totalMemory() - runtime.freeMemory();
//    }
//
//    private void writeResultsToFile(long[] memoryConsumption512, long[] memoryConsumption768, long[] memoryConsumption1024) {
//        try (BufferedWriter writer = new BufferedWriter(new FileWriter("KyberTestsResults/Full_Process_Of_Kyber_Memory_Consumption.txt"))) {
//            writeResults(writer, "Kyber512", memoryConsumption512);
//            writeResults(writer, "Kyber768", memoryConsumption768);
//            writeResults(writer, "Kyber1024", memoryConsumption1024);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//
//    private void writeResults(BufferedWriter writer, String name, long[] memoryConsumption) throws IOException {
//        // Convert bytes to megabytes
//        double[] memoryConsumptionMB = Arrays.stream(memoryConsumption)
//                .mapToDouble(memory -> (double) memory / (1024 * 1024))
//                .toArray();
//
//        writer.write(name + " Memory Consumption tests for key pair generation and secret key encapsulation: \n");
//        writer.write("======================================================================================\n");
//        writer.write("Largest Memory Consumption: " + findLargest(memoryConsumptionMB) + " megabytes\n");
//        writer.write("Smallest Memory Consumption: " + findSmallest(memoryConsumptionMB) + " megabytes\n");
//        writer.write("Average Memory Consumption: " + calculateAverage(memoryConsumptionMB) + " megabytes\n");
//        writer.write("Standard Deviation: " + calculateStandardDeviation(memoryConsumptionMB) + " megabytes\n");
//
//        writer.write("======================================================================================\n\n");
//    }
//
//
//
//    private double calculateStandardDeviation(double[] memoryConsumption) {
//        double mean = calculateAverage(memoryConsumption);
//
//        double sumSquaredDifferences = Arrays.stream(memoryConsumption)
//                .map(memory -> Math.pow(memory - mean, 2))
//                .sum();
//
//        return Math.sqrt(sumSquaredDifferences / memoryConsumption.length);
//    }
//
//
//    private double findLargest(double[] memoryConsumption) {
//        double largest = Double.MIN_VALUE;
//
//        for (int i = 0; i < memoryConsumption.length; i++) {
//            if (memoryConsumption[i] > largest) {
//                largest = memoryConsumption[i];
//            }
//        }
//
//        return largest;
//    }
//
//    private double findSmallest(double[] memoryConsumption) {
//        double smallest = Double.MAX_VALUE;
//
//        for (int i = 0; i < memoryConsumption.length; i++) {
//            if (memoryConsumption[i] < smallest) {
//                smallest = memoryConsumption[i];
//            }
//        }
//
//        return smallest;
//    }
//
//
//    private double calculateAverage(double[] memoryConsumption) {
//        double sum = 0;
//
//        for (int i = 0; i < memoryConsumption.length; i++) {
//            sum += memoryConsumption[i];
//        }
//
//        return sum / memoryConsumption.length;
//    }
//
//}
