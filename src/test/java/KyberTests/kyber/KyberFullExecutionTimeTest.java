package KyberTests.kyber;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.example.kyber.KyberAlgo;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;

public class KyberFullExecutionTimeTest {

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
        System.gc();

        // Warm-up Kyber512
        warmUpKyber(KyberParameterSpec.kyber512);
        System.gc();
        // Test Kyber512
        testKyberExecutionTime(KyberParameterSpec.kyber512, executionTimes512);
        System.gc();
        // Test Kyber768
        testKyberExecutionTime(KyberParameterSpec.kyber768, executionTimes768);
        System.gc();
        // Test Kyber1024
        testKyberExecutionTime(KyberParameterSpec.kyber1024, executionTimes1024);
        System.gc();
        // Write results to a file
        writeResultsToFile(executionTimes512, executionTimes768, executionTimes1024);
    }

    private void warmUpKyber(KyberParameterSpec kyberParameterSpec) throws Exception {
        Method generateKeyPairMethod = KyberAlgo.class.getDeclaredMethod("generateKeyPair", KyberParameterSpec.class);
        generateKeyPairMethod.setAccessible(true);
        Method generateSecretKeySenderMethod = KyberAlgo.class.getDeclaredMethod("generateSecretKeySender", PublicKey.class);
        generateSecretKeySenderMethod.setAccessible(true);

        KeyPair warmUpKeyPair = (KeyPair) generateKeyPairMethod.invoke(null, kyberParameterSpec);
        generateSecretKeySenderMethod.invoke(null, warmUpKeyPair.getPublic());
    }

    private void testKyberExecutionTime(KyberParameterSpec kyberParameterSpec, double[] executionTimes) throws Exception {
        Method generateKeyPairMethod = KyberAlgo.class.getDeclaredMethod("generateKeyPair", KyberParameterSpec.class);
        generateKeyPairMethod.setAccessible(true);
        Method generateSecretKeySenderMethod = KyberAlgo.class.getDeclaredMethod("generateSecretKeySender", PublicKey.class);
        generateSecretKeySenderMethod.setAccessible(true);

        for (int i = 0; i < executionTimes.length; i++) {
            long startTime = System.nanoTime();
            // Generate key pair and encapsulation
            KeyPair keyPair = (KeyPair) generateKeyPairMethod.invoke(null, kyberParameterSpec);
            generateSecretKeySenderMethod.invoke(null, keyPair.getPublic());
            executionTimes[i] = (System.nanoTime() - startTime) / 1_000_000.0;
        }

    }

    private void writeResultsToFile(double[] executionTimes512, double[] executionTimes768, double[] executionTimes1024) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("KyberTestsResults/kyber_full_execution_times.txt"))) {
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
}
