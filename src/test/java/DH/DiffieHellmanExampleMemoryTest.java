package DH;

import org.example.kyber.DH;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;

public class DiffieHellmanExampleMemoryTest {

    @BeforeClass
    public static void setUp() {
        // Add Bouncy Castle provider for Diffie-Hellman
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    @Test
    public void testDiffieHellmanMemoryConsumption() throws Exception {
        int warmUpIterations = 5;
        int numberOfExecutions = 1000;

        // Warm-up Diffie-Hellman
        for (int i = 0; i < warmUpIterations; i++) {
            runDiffieHellmanTest();
        }

        // Arrays to store memory consumption
        long[] memoryConsumption = new long[numberOfExecutions];

        // Test Diffie-Hellman
        for (int i = 0; i < numberOfExecutions; i++) {
            memoryConsumption[i] = runDiffieHellmanTest();
        }

        // Write results to a file
        writeResultsToFile(memoryConsumption);
    }

    private long runDiffieHellmanTest() throws Exception {
        // Run garbage collection before each measurement
        System.gc();
        long startMemory = getMemoryUsage();

        // Generate key pairs for Diffie-Hellman
        KeyPair keyPairA = DH.generateKeyPair();
        KeyPair keyPairB = DH.generateKeyPair();

        // Generate shared secrets
        byte[] secretA = DH.generateSharedSecret(keyPairA.getPrivate(), keyPairB.getPublic());
        byte[] secretB = DH.generateSharedSecret(keyPairB.getPrivate(), keyPairA.getPublic());

        // Compare shared secrets
        //DH.compareSharedSecrets(secretA, secretB);

        return getMemoryUsage() - startMemory;
    }

    private long getMemoryUsage() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }

    private void writeResultsToFile(long[] memoryConsumption) {
        // Create the directory if it doesn't exist
        File directory = new File("DiffieHellmanTestsResults");
        if (!directory.exists()) {
            directory.mkdirs();
        }

        // Write results to a file
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("DHTestsResults/Memory_Consumption.txt"))) {
            writeResults(writer, "Diffie-Hellman", memoryConsumption);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void writeResults(BufferedWriter writer, String name, long[] memoryConsumption) throws IOException {
        // Convert bytes to megabytes
        double[] memoryConsumptionMB = Arrays.stream(memoryConsumption)
                .mapToDouble(memory -> (double) memory / (1024 * 1024))
                .toArray();

        writer.write(name + " Memory Consumption tests for key pair generation and shared secret generation: \n");
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


//package DH;
//
//import org.example.kyber.DiffieHellmanExample;
//import org.junit.Test;
//
//import java.io.FileWriter;
//import java.io.IOException;
//import java.security.KeyPair;
//import java.security.PublicKey;
//import java.util.ArrayList;
//import java.util.DoubleSummaryStatistics;
//import java.util.List;
//
//public class DiffieHellmanExampleMemoryTest {
//
//    @Test
//    public void testMemoryConsumption() throws Exception {
//        List<Long> memoryUsages = new ArrayList<>();
//
//        for (int i = 0; i < 1000; i++) {
//            Runtime runtime = Runtime.getRuntime();
//            runtime.gc();
//            Thread.sleep(10);
//
//            // Creating a new object to encourage garbage collection
//            DiffieHellmanExample diffieHellmanExample = new DiffieHellmanExample();
//            KeyPair keyPair = diffieHellmanExample.generateKeyPair();
//            PublicKey publicKey = diffieHellmanExample.generatePublicKey(keyPair.getPublic().getEncoded());
//            byte[] sharedSecret = diffieHellmanExample.generateSharedSecret(keyPair, publicKey);
//
//            runtime.gc();
//            Thread.sleep(10);
//
//            long beforeUsedMem = runtime.totalMemory() - runtime.freeMemory();
//
//            // Performing a task that involves memory allocation
//            performMemoryIntensiveTask();
//
//            long afterUsedMem = runtime.totalMemory() - runtime.freeMemory();
//            long consumed = (afterUsedMem - beforeUsedMem) / 1024 / 1024;
//            memoryUsages.add(consumed);
//        }
//
//        DoubleSummaryStatistics stats = memoryUsages.stream()
//                .mapToDouble((x) -> x)
//                .summaryStatistics();
//
//        double sum = 0.0;
//        for (long memoryUsage : memoryUsages) {
//            sum += Math.pow(memoryUsage - stats.getAverage(), 2);
//        }
//        double standardDeviation = Math.sqrt(sum / (memoryUsages.size() - 1));
//
//        try (FileWriter fileWriter = new FileWriter("DhTestsResults/memoryConsumption.txt")) {
//            fileWriter.write("Smallest Memory Consumption: " + stats.getMin() + " MB\n");
//            fileWriter.write("Largest Memory Consumption: " + stats.getMax() + " MB\n");
//            fileWriter.write("Average Memory Consumption: " + stats.getAverage() + " MB\n");
//            fileWriter.write("Standard Deviation of Memory Consumption: " + standardDeviation + " MB\n");
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//
//    private void performMemoryIntensiveTask() {
//        // Simulate a memory-intensive task
//        // Allocate some objects, perform operations, etc.
//        // This will help in detecting memory changes more accurately
//        // Example: Create and manipulate large data structures
//        List<Integer> dummyList = new ArrayList<>();
//        for (int j = 0; j < 100000; j++) {
//            dummyList.add(j);
//        }
//    }
//}
