package diffieHellmanTests.diffTest;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import static org.junit.Assert.assertTrue;

public class DhKeyPairGenExecTimeTest {

    @BeforeClass
    public static void setUp() {
        // Add Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void a_testKeyPairGenerationTime() throws Exception {
        int numberOfExecutions = 1000;
        long[] generationTimes = new long[numberOfExecutions];

        // Warm-up with fewer iterations
        for (int i = 0; i < 5; i++) {
            generateKeyPair();
        }

        for (int i = 0; i < generationTimes.length; i++) {
            long startTime = System.nanoTime();

            // Perform DH key pair generation
            generateKeyPair();

            generationTimes[i] = System.nanoTime() - startTime;

            // No additional testing considerations needed for key pair generation
            assertTrue(generationTimes[i] > 0); // Ensure that execution time is greater than 0
        }

        // Write results to a file or print to the console
        writeResultsToFile(generationTimes);
    }

    private void writeResultsToFile(long[] generationTimes) {
        // Implement file writing logic or print to the console as needed
        System.out.println("Key Pair Generation Time tests:\n");
        System.out.println("======================================================================================\n");
        System.out.println("Longest Generation Time: " + findLongest(generationTimes) / 1_000_000.0 + " ms\n");
        System.out.println("Shortest Generation Time: " + findShortest(generationTimes) / 1_000_000.0 +  " ms\n");
        System.out.println("Average Generation Time: " + calculateAverage(generationTimes) / 1_000_000.0 + " ms\n");
        System.out.println("======================================================================================\n\n");
    }

    private long findLongest(long[] times) {
        long longest = Long.MIN_VALUE;
        for (long time : times) {
            if (time > longest) {
                longest = time;
            }
        }
        return longest;
    }

    private long findShortest(long[] times) {
        long shortest = Long.MAX_VALUE;
        for (long time : times) {
            if (time < shortest) {
                shortest = time;
            }
        }
        return shortest;
    }

    private double calculateAverage(long[] times) {
        long sum = 0;
        for (long time : times) {
            sum += time;
        }
        return (double) sum / times.length;
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", "BC");
        keyPairGenerator.initialize(2048); // Adjust key size as needed
        return keyPairGenerator.generateKeyPair();
    }
}



//package diffieHellmanTests.diffTest;
//
///**
// * @author Amine_Mighri
// */
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.example.diff.Dh;
//import org.junit.BeforeClass;
//import org.junit.Test;
//
//import java.io.BufferedWriter;
//import java.io.File;
//import java.io.FileWriter;
//import java.io.IOException;
//import java.security.KeyPair;
//import java.security.Security;
//
//public class DhKeyPairGenExecTimeTest {
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
//        double[] executionTimes2048 = new double[numberOfExecutions];
//        System.gc();
//        // Warm-up DH with 2048 bits
//        warmUpDh(2048);
//        System.gc();
//        // Test DH with 2048 bits
//        testDhExecutionTime(2048, executionTimes2048);
//        System.gc();
//        // Write results to a file
//        writeResultsToFile(executionTimes2048);
//    }
//
//    private void warmUpDh(int keySize) throws Exception {
//        KeyPair warmUpKeyPair = Dh.generateKeyPair(); // You can modify the method if needed
//    }
//
//    private void testDhExecutionTime(int keySize, double[] executionTimes) throws Exception {
//        for (int i = 0; i < executionTimes.length; i++) {
//            long startTime = System.nanoTime();
//            // Generate DH key pair
//            KeyPair keyPair = Dh.generateKeyPair();
//            executionTimes[i] = (System.nanoTime() - startTime) / 1_000_000.0;
//        }
//    }
//
//    private void writeResultsToFile(double[] executionTimes2048) {
//        String filePath = "DhTestsResults" + File.separator + "dh_keypair_execution_times.txt";
//
//        try {
//            File directory = new File("DhTestsResults");
//            if (!directory.exists()) {
//                directory.mkdirs(); // Creates the directory and any necessary parent directories
//            }
//
//            try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
//                writeResults(writer, "DH2048", executionTimes2048);
//            }
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//
//    private void writeResults(BufferedWriter writer, String name, double[] executionTimes) throws IOException {
//        writer.write(name + " Execution Time tests for key pair generation : \n");
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
