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
//        try (FileWriter fileWriter = new FileWriter("memoryConsumption.txt")) {
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
