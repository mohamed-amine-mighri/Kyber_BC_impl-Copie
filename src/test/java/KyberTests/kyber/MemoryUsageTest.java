package KyberTests.kyber;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.example.kyber.KyberAlgo;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;

public class MemoryUsageTest {

    @BeforeClass
    public static void setUp() {
        // Add Bouncy Castle PQC provider
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    @Test
    public void testKyberMemoryUsage() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

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
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("KyberTestsResults/kyber_memory_usage.txt"))) {
            writer.write("Kyber memory usgae tests for key pair generation and secret key encapsulation: \n");
            writer.write("======================================================================================\n");
            writer.write("\n");
            // Writing Kyber512 results
            writer.write("Kyber512: Maximum Memory Usage: " + findMaximum(memoryUsage512) + " megabytes\n");
            writer.write("Kyber512: Minimum Memory Usage: " + findMinimum(memoryUsage512) + " megabytes\n");
            writer.write("Kyber512: Average Memory Usage: " + calculateAverage(memoryUsage512) + " megabytes\n");
            writer.write("======================================================================================\n");

            // Writing Kyber768 results
            writer.write("Kyber768: Maximum Memory Usage: " + findMaximum(memoryUsage768) + " megabytes\n");
            writer.write("Kyber768: Minimum Memory Usage: " + findMinimum(memoryUsage768) + " megabytes\n");
            writer.write("Kyber768: Average Memory Usage: " + calculateAverage(memoryUsage768) + " megabytes\n");
            writer.write("======================================================================================\n");

            // Writing Kyber1024 results
            writer.write("Kyber1024: Maximum Memory Usage: " + findMaximum(memoryUsage1024) + " megabytes\n");
            writer.write("Kyber1024: Minimum Memory Usage: " + findMinimum(memoryUsage1024) + " megabytes\n");
            writer.write("Kyber1024: Average Memory Usage: " + calculateAverage(memoryUsage1024) + " megabytes\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private double runKyberTest(KyberParameterSpec kyberParameterSpec) throws Exception {
        // Run garbage collection before each measurement
        System.gc();
        long startMemory = getMemoryUsage();
        // Generate key pair and encapsulation for Kyber
        KeyPair keyPair = generateKeyPairWithReflection(kyberParameterSpec);
        generateSecretKeySenderWithReflection(keyPair.getPublic());
        return (getMemoryUsage() - startMemory) / (1024.0 * 1024.0); // Convert to megabytes
    }

    private KeyPair generateKeyPairWithReflection(KyberParameterSpec kyberParameterSpec) throws Exception {
        Method method = KyberAlgo.class.getDeclaredMethod("generateKeyPair", KyberParameterSpec.class);
        method.setAccessible(true);
        return (KeyPair) method.invoke(null, kyberParameterSpec);
    }

    private SecretKeyWithEncapsulation generateSecretKeySenderWithReflection(PublicKey publicKey) throws Exception {
        Method method = KyberAlgo.class.getDeclaredMethod("generateSecretKeySender", PublicKey.class);
        method.setAccessible(true);
        return (SecretKeyWithEncapsulation) method.invoke(null, publicKey);
    }

    private long getMemoryUsage() {
        return ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed();
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

