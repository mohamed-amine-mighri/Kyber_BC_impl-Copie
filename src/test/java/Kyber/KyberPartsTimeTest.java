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

public class KyberPartsTimeTest {

    @BeforeClass
    public static void setUp() {
        // Add Bouncy Castle PQC provider
        Security.addProvider(new BouncyCastlePQCProvider());
    }


    @Test
    public void testKyberExecutionTimes() throws Exception {
        int numberOfExecutions = 1000;

        // Arrays to store execution times
        double[] keyGenerationTimes512 = new double[numberOfExecutions];
        double[] encapsulationTimes512 = new double[numberOfExecutions];
        double[] decapsulationTimes512 = new double[numberOfExecutions];

        double[] keyGenerationTimes768 = new double[numberOfExecutions];
        double[] encapsulationTimes768 = new double[numberOfExecutions];
        double[] decapsulationTimes768 = new double[numberOfExecutions];

        double[] keyGenerationTimes1024 = new double[numberOfExecutions];
        double[] encapsulationTimes1024 = new double[numberOfExecutions];
        double[] decapsulationTimes1024 = new double[numberOfExecutions];

        // Warm-up Kyber512
        warmUpKyber();

        // Test Kyber512
        testKyberExecutionTime(KyberParameterSpec.kyber512, keyGenerationTimes512, encapsulationTimes512, decapsulationTimes512);

        // Test Kyber768
        testKyberExecutionTime(KyberParameterSpec.kyber768, keyGenerationTimes768, encapsulationTimes768, decapsulationTimes768);

        // Test Kyber1024
        testKyberExecutionTime(KyberParameterSpec.kyber1024, keyGenerationTimes1024, encapsulationTimes1024, decapsulationTimes1024);

        // Write results to a file
        writeResultsToFile("KyberTestsResults/kyber_Parts_execution_times.txt", "Kyber512", keyGenerationTimes512, encapsulationTimes512, decapsulationTimes512);
        writeResultsToFile("KyberTestsResults/kyber_Parts_execution_times.txt", "Kyber768", keyGenerationTimes768, encapsulationTimes768, decapsulationTimes768);
        writeResultsToFile("KyberTestsResults/kyber_Parts_execution_times.txt", "Kyber1024", keyGenerationTimes1024, encapsulationTimes1024, decapsulationTimes1024);
    }

    private void warmUpKyber() throws Exception {
        System.out.println("Warm-up Kyber...");
        performKyberWarmUp();
        System.out.println("Warm-up completed.");
    }

    private void performKyberWarmUp() throws Exception {
        // Warm-up loop
        for (int j = 0; j < 10000; j++) { // Same number of iterations for all Kyber variations
            KeyPair senderKeyPair = KyberExample.generateKeyPair(KyberParameterSpec.kyber512);
            PublicKey senderPublicKey = senderKeyPair.getPublic();

            SecretKeyWithEncapsulation secretKeyWithEncapsulation = KyberExample.generateSecretKeySender(senderPublicKey);
            byte[] encapsulation = secretKeyWithEncapsulation.getEncapsulation();

            KeyPair receiverKeyPair = KyberExample.generateKeyPair(KyberParameterSpec.kyber512);
            PrivateKey receiverPrivateKey = receiverKeyPair.getPrivate();

            KyberExample.generateSecretKeyReceiver(receiverPrivateKey, encapsulation);
        }
    }

    private void testKyberExecutionTime(KyberParameterSpec kyberParameterSpec, double[] keyGenerationTimes, double[] encapsulationTimes, double[] decapsulationTimes) throws Exception {
        System.out.println("Testing Kyber" + kyberParameterSpec.getName() + "...");
        performKyberTests(kyberParameterSpec, keyGenerationTimes, encapsulationTimes, decapsulationTimes);
        System.out.println("Testing completed.");
    }

    private void performKyberTests(KyberParameterSpec kyberParameterSpec, double[] keyGenerationTimes, double[] encapsulationTimes, double[] decapsulationTimes) throws Exception {
        System.gc();
        for (int i = 0; i < keyGenerationTimes.length; i++) {
            long startTimeKeyGeneration = System.nanoTime();
            // Generate key pair
            KeyPair senderKeyPair = KyberExample.generateKeyPair(kyberParameterSpec);
            KeyPair receiverKeyPair = KyberExample.generateKeyPair(kyberParameterSpec);
            keyGenerationTimes[i] = (System.nanoTime() - startTimeKeyGeneration) / 1000000.0;

            // Generate encapsulation
            long startTimeEncapsulation = System.nanoTime();
            PublicKey senderPublicKey = senderKeyPair.getPublic();
            SecretKeyWithEncapsulation secretKeyWithEncapsulation = KyberExample.generateSecretKeySender(senderPublicKey);
            byte[] encapsulation = secretKeyWithEncapsulation.getEncapsulation();
            encapsulationTimes[i] = (System.nanoTime() - startTimeEncapsulation) / 1000000.0;

            // Generate decapsulation
            long startTimeDecapsulation = System.nanoTime();
            PrivateKey receiverPrivateKey = receiverKeyPair.getPrivate();
            KyberExample.generateSecretKeyReceiver(receiverPrivateKey, encapsulation);
            decapsulationTimes[i] = (System.nanoTime() - startTimeDecapsulation) / 1000000.0;
        }
    }

    private void writeResultsToFile(String filePath, String name, double[] keyGenerationTimes, double[] encapsulationTimes, double[] decapsulationTimes) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath, true))) {
            writeResults(writer, name, "Key Generation", keyGenerationTimes);
            writeResults(writer, name, "Encapsulation", encapsulationTimes);
            writeResults(writer, name, "Decapsulation", decapsulationTimes);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void writeResults(BufferedWriter writer, String name, String process, double[] executionTimes) throws IOException {
        writer.write(name + " " + process + " Execution Time tests: \n");
        writer.write("======================================================================================\n");

        // Exclude the longest execution time from the calculations
        double longestTime = findLongest(executionTimes);
        double[] executionTimesWithoutLongest = Arrays.stream(executionTimes)
                .filter(time -> time != longestTime)
                .toArray();

        // Calculate statistics excluding the longest time
        writer.write("Shortest Execution Time: " + findShortest(executionTimes) + " ms\n");
        writer.write("Average Execution Time: " + calculateAverage(executionTimesWithoutLongest) + " ms\n");
        writer.write("Standard Deviation: " + calculateStandardDeviation(executionTimesWithoutLongest) + " ms\n");

        // Find the third longest execution time
        Arrays.sort(executionTimesWithoutLongest); // Sort the execution times
        int thirdLongestIndex = Math.max(0, executionTimesWithoutLongest.length - 3); // Index of the third longest time
        double thirdLongest = executionTimesWithoutLongest[thirdLongestIndex];

        writer.write("Third Longest Execution Time: " + thirdLongest + " ms\n");

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
