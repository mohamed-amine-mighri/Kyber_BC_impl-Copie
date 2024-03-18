package Kyber;

/**
 * @author Amine_Mighri
 */

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.example.kyber.KyberExample;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class KyberMemoryConsumptionExamplTest {

    private static final int NUM_EXECUTIONS = 1000;
    private static final String FILENAME = "kyber_memory_usage.txt";
    private static final int WARM_UP_ITERATIONS = 5;

    private static ArrayList<Long> memoryConsumptions512 = new ArrayList<>();
    private static ArrayList<Long> memoryConsumptions768 = new ArrayList<>();
    private static ArrayList<Long> memoryConsumptions1024 = new ArrayList<>();

    @BeforeAll
    public static void setUp() {
        // Add Bouncy Castle PQC provider
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    @Test
    public void testKyberMemoryConsumption() throws Exception {
        // Warm-up Kyber512
        for (int i = 0; i < WARM_UP_ITERATIONS; i++) {
            runKyberTest(KyberParameterSpec.kyber512);
        }

        // Test Kyber512
        for (int i = 0; i < NUM_EXECUTIONS; i++) {
            memoryConsumptions512.add(runKyberTest(KyberParameterSpec.kyber512));
        }

        // Test Kyber768
        for (int i = 0; i < NUM_EXECUTIONS; i++) {
            memoryConsumptions768.add(runKyberTest(KyberParameterSpec.kyber768));
        }

        // Test Kyber1024
        for (int i = 0; i < NUM_EXECUTIONS; i++) {
            memoryConsumptions1024.add(runKyberTest(KyberParameterSpec.kyber1024));
        }

        // Write results to a file
        writeResultsToFile(memoryConsumptions512, memoryConsumptions768, memoryConsumptions1024);
    }

    private long runKyberTest(KyberParameterSpec kyberParameterSpec) throws Exception {
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
        return getMemoryUsage() - startMemory;
    }

    private long getMemoryUsage() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }

    private void writeResultsToFile(List<Long> memoryConsumptions512, List<Long> memoryConsumptions768, List<Long> memoryConsumptions1024) {
        try (FileWriter writer = new FileWriter(FILENAME)) {
            writeResults(writer, "Kyber512", memoryConsumptions512);
            writeResults(writer, "Kyber768", memoryConsumptions768);
            writeResults(writer, "Kyber1024", memoryConsumptions1024);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void writeResults(FileWriter writer, String name, List<Long> memoryConsumptions) throws IOException {
        // Convert bytes to megabytes
        double[] memoryConsumptionMB = memoryConsumptions.stream()
                .mapToDouble(memory -> (double) memory / (1024 * 1024))
                .toArray();

        writer.write(name + " Memory Consumption tests for key pair generation and secret key encapsulation: \n");
        writer.write("======================================================================================\n");
        writer.write("Largest Memory Consumption: " + findLargest(memoryConsumptionMB) + " megabytes\n");
        writer.write("Smallest Memory Consumption: " + findSmallest(memoryConsumptionMB) + " megabytes\n");
        writer.write("Average Memory Consumption: " + calculateAverage(memoryConsumptionMB) + " megabytes\n");
        writer.write("Standard Deviation: " + calculateStandardDeviation(memoryConsumptionMB) + " megabytes\n");

        writer.write("======================================================================================\n\n");
    }

    private double calculateStandardDeviation(double[] memoryConsumption) {
        double mean = calculateAverage(memoryConsumption);

        double sumSquaredDifferences = Arrays.stream(memoryConsumption)
                .map(memory -> Math.pow(memory - mean, 2))
                .sum();

        return Math.sqrt(sumSquaredDifferences / memoryConsumption.length);
    }

    private double findLargest(double[] memoryConsumption) {
        double largest = Double.MIN_VALUE;

        for (int i = 0; i < memoryConsumption.length; i++) {
            if (memoryConsumption[i] > largest) {
                largest = memoryConsumption[i];
            }
        }

        return largest;
    }

    private double findSmallest(double[] memoryConsumption) {
        double smallest = Double.MAX_VALUE;

        for (int i = 0; i < memoryConsumption.length; i++) {
            if (memoryConsumption[i] < smallest) {
                smallest = memoryConsumption[i];
            }
        }

        return smallest;
    }

    private double calculateAverage(double[] memoryConsumption) {
        double sum = 0;

        for (int i = 0; i < memoryConsumption.length; i++) {
            sum += memoryConsumption[i];
        }

        return sum / memoryConsumption.length;
    }
}
