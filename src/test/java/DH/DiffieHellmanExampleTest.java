//package DH;
//
///**
// * @author Amine_Mighri
// */
//
//import org.example.kyber.DiffieHellmanExample;
//import org.junit.Test;
//
//import java.io.BufferedWriter;
//import java.io.FileWriter;
//import java.io.IOException;
//import java.util.ArrayList;
//import java.util.List;
//import java.util.OptionalDouble;
//import java.util.OptionalLong;
//
//public class DiffieHellmanExampleTest {
//
//    @Test
//    public void testExecutionTime() throws Exception {
//        // JVM warm-up phase
//        for (int i = 0; i < 100; i++) {
//            DiffieHellmanExample.main(new String[]{});
//        }
//
//        List<Long> executionTimes = new ArrayList<>();
//        for (int i = 0; i < 1000; i++) {
//            long startTime = System.nanoTime();
//
//            // Call the main method
//            DiffieHellmanExample.main(new String[]{});
//
//            long endTime = System.nanoTime();
//
//            // Get the difference in time
//            long timeElapsed = endTime - startTime;
//            executionTimes.add(timeElapsed);
//        }
//
//        OptionalLong maxTime = executionTimes.stream().mapToLong(Long::longValue).max();
//        OptionalLong minTime = executionTimes.stream().mapToLong(Long::longValue).min();
//        OptionalDouble averageTime = executionTimes.stream().mapToLong(Long::longValue).average();
//
//        double sumOfSquare = executionTimes.stream().mapToDouble(i -> Math.pow(i - averageTime.getAsDouble(), 2)).sum();
//        double standardDeviation = Math.sqrt(sumOfSquare / executionTimes.size());
//
//        try (BufferedWriter writer = new BufferedWriter(new FileWriter("DhTestsResults/KyberExecutionTimeExampleTest.txt"))) {
//            writer.write("Max execution time: " + maxTime.getAsLong() / 1000000 + " ms\n");
//            writer.write("Min execution time: " + minTime.getAsLong() / 1000000 + " ms\n");
//            writer.write("Average execution time: " + averageTime.getAsDouble() / 1000000 + " ms\n");
//            writer.write("Standard deviation: " + standardDeviation / 1000000 + " ms\n");
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//}
