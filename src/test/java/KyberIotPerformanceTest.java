import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.example.kyber.KyberExample;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import static org.junit.Assert.assertTrue;

public class KyberIotPerformanceTest {
//    final protected static char[] hexArray = "0123456789abcdef".toCharArray();

    @Test
    public void testKyberEncryptionDecryption() throws Exception {
        double startTime, endTime, totalDuration = 0;

        // Initialize Kyber parameters
        KyberParameterSpec kyberParameterSpec = KyberParameterSpec.kyber1024;

        // Create a FileWriter and BufferedWriter to write to a file

        for (int i = 0; i < 1000; i++) {
            // Generate key pair
            startTime = System.nanoTime();
            KeyPair keyPair = KyberExample.generateKeyPair(kyberParameterSpec);

            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Generate secret key for the sender
            SecretKeyWithEncapsulation senderKeyWithEncapsulation = KyberExample.generateSecretKeySender(publicKey);

            byte[] senderSecretKey = senderKeyWithEncapsulation.getEncoded();
            byte[] encapsulation = senderKeyWithEncapsulation.getEncapsulation();

            // Generate secret key for the receiver using the encapsulated data
            SecretKeyWithEncapsulation receiverKeyWithEncapsulation = KyberExample.generateSecretKeyReceiver(privateKey, encapsulation);

            byte[] receiverSecretKey = receiverKeyWithEncapsulation.getEncoded();

            // Simulate an IoT packet
            String iotData = "This is a test IoT packet";
            byte[] iotPacket = iotData.getBytes();
            int iotPacketLength = iotPacket.length;
            System.out.println("Length of IoT packet: " + iotPacketLength + " bytes");

            // Encrypt the packet using the sender's secret key
            byte[] encryptedPacket = KyberExample.encrypt(iotPacket, senderSecretKey);

            // Decrypt the packet using the receiver's secret key
            byte[] decryptedPacket = KyberExample.decrypt(encryptedPacket, receiverSecretKey);
            endTime = System.nanoTime();
            double duration = (endTime - startTime) / 1000000.0;
            totalDuration += duration;

            System.out.println("Decryption time: " + duration + " ms");

            // Verify that the original data is equal to the decrypted data
            assertTrue("Decrypted data should match the original data.", Arrays.equals(iotPacket, decryptedPacket));

            // Write the duration to the file

        }

        // Calculate and print the average duration
        double averageDuration = totalDuration / 1000.0;
        System.out.println("Average execution time: " + averageDuration + " ms");

        // Close the BufferedWriter
    }
//
//    public static String bytesToHex(byte[] bytes) {
//        char[] hexChars = new char[bytes.length * 2];
//        for (int j = 0; j < bytes.length; j++) {
//            int v = bytes[j] & 0xFF;
//            hexChars[j * 2] = hexArray[v >>> 4];
//            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
//        }
//        return new String(hexChars);
//    }
}
