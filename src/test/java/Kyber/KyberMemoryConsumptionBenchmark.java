/**
 * @author Amine_Mighri
 */
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.example.kyber.KyberExample;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;


import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.Throughput)
@Warmup(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 10, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(1)
@State(Scope.Benchmark)

public class KyberMemoryConsumptionBenchmark {

    private KyberParameterSpec kyberParameterSpec;

    @Setup(Level.Trial)
    public void setup() {
        // Initialize providers only once at the beginning of the trial
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
        kyberParameterSpec = KyberParameterSpec.kyber512;
    }

    @Benchmark
    public long measureKyberMemoryConsumption() throws Exception {
        return runKyberTest(kyberParameterSpec);
    }

    private long runKyberTest(KyberParameterSpec kyberParameterSpec) throws Exception {
        System.gc();
        long startMemory = getMemoryUsage();

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

    public static void main(String[] args) throws RunnerException {
        Options options = new OptionsBuilder()
                .include(KyberMemoryConsumptionBenchmark.class.getSimpleName())
                .build();

        new Runner(options).run();
    }
    private void writeResultsToFile(long[] memoryConsumption512, long[] memoryConsumption768, long[] memoryConsumption1024) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("KyberTestsResults/Memory_Consumption.txt"))) {
            writeResults(writer, "Kyber512", memoryConsumption512);
            writeResults(writer, "Kyber768", memoryConsumption768);
            writeResults(writer, "Kyber1024", memoryConsumption1024);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void writeResults(BufferedWriter writer, String name, long[] memoryConsumption) throws IOException {
        // Convert bytes to megabytes
        double[] memoryConsumptionMB = Arrays.stream(memoryConsumption)
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

        for (double memory : memoryConsumption) {
            if (memory > largest) {
                largest = memory;
            }
        }

        return largest;
    }

    private double findSmallest(double[] memoryConsumption) {
        double smallest = Double.MAX_VALUE;

        for (double memory : memoryConsumption) {
            if (memory < smallest) {
                smallest = memory;
            }
        }

        return smallest;
    }

    private double calculateAverage(double[] memoryConsumption) {
        double sum = Arrays.stream(memoryConsumption).sum();
        return sum / memoryConsumption.length;
    }
}
