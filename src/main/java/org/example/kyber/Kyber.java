package org.example.kyber;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.*;
import java.util.Scanner;

/**
 * @author Amine_Mighri
 */
public class Kyber {

    private static final String KEM_ALGORITHM = "Kyber";
    private static final String PROVIDER = "BCPQC";
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String MODE_PADDING = "AES/ECB/PKCS5Padding";

    public static byte[] encrypt(byte[] plainBytes, byte[] key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, ENCRYPTION_ALGORITHM);
        Cipher cipher = Cipher.getInstance(MODE_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plainBytes);
    }

    public static byte[] decrypt(byte[] encryptedBytes, byte[] key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, ENCRYPTION_ALGORITHM);
        Cipher cipher = Cipher.getInstance(MODE_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(encryptedBytes);
    }

    private static KeyPair generateKeyPair(KyberParameterSpec kyberParameterSpec) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEM_ALGORITHM, PROVIDER);
        keyPairGenerator.initialize(kyberParameterSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    private static SecretKeyWithEncapsulation generateSecretKeySender(PublicKey publicKey) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEM_ALGORITHM, PROVIDER);
        KEMGenerateSpec kemGenerateSpec = new KEMGenerateSpec(publicKey, "Secret");
        keyGenerator.init(kemGenerateSpec);
        return (SecretKeyWithEncapsulation) keyGenerator.generateKey();
    }

    private static SecretKeyWithEncapsulation generateSecretKeyReceiver(PrivateKey privateKey, byte[] encapsulation) throws Exception {
        KEMExtractSpec kemExtractSpec = new KEMExtractSpec(privateKey, encapsulation, "Secret");
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEM_ALGORITHM, PROVIDER);
        keyGenerator.init(kemExtractSpec);
        return (SecretKeyWithEncapsulation) keyGenerator.generateKey();
    }

    // Read the input file from resources package
    private static byte[] readFileFromResources(String resourceName) throws Exception {
        try (InputStream inputStream = Kyber.class.getResourceAsStream(resourceName)) {
            if (inputStream == null) {
                throw new IllegalArgumentException("Resource not found: " + resourceName);
            }
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int length;
            while ((length = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, length);
            }
            return outputStream.toByteArray();
        }
    }

    private static void writeFile(String path, byte[] content) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(content);
        }
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());

        // Allow the user to choose Kyber version
        Scanner scanner = new Scanner(System.in);
        System.out.println("Choose Kyber version (1024, 768, or 512): ");
        int kyberVersion = scanner.nextInt();

        // Validate user input
        if (kyberVersion != 1024 && kyberVersion != 768 && kyberVersion != 512) {
            System.out.println("Invalid Kyber version. Exiting...");
            return;
        }

        KyberParameterSpec kyberParameterSpec = null;

        // Set KyberParameterSpec based on user input
        switch (kyberVersion) {
            case 1024:
                kyberParameterSpec = KyberParameterSpec.kyber1024;
                break;
            case 768:
                kyberParameterSpec = KyberParameterSpec.kyber768;
                break;
            case 512:
                kyberParameterSpec = KyberParameterSpec.kyber512;
                break;
        }

        // Start timing and memory usage measurement for Kyber generation and encapsulation
        long startTime = System.nanoTime();
        long startMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();

        // Get Kyber key pair based on user input
        KeyPair keyPair = generateKeyPair(kyberParameterSpec);

        SecretKeyWithEncapsulation initKeyWithEnc = generateSecretKeySender(keyPair.getPublic());
        byte[] encapsulation = initKeyWithEnc.getEncapsulation();


        long endMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        long endTime = System.nanoTime();

        long memoryUsed = endMemory - startMemory;
        double seconds = (endTime - startTime) / 1_000_000.0;
        double memoryUsedInMGB = memoryUsed / (double)(1024 * 1024);
        System.out.println("Kyber generation and encapsulation time: " + seconds + " ms");
        System.out.println("Memory used for Kyber generation and encapsulation: " + memoryUsedInMGB + " megabytes");



        // AES encryption and decryption measurement starts here
        startTime = System.nanoTime();
        startMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();


        // Replace "inputFileName.ext" with your actual file name located in the resources folder.
        byte[] fileContent = readFileFromResources("/inPut/inputText1.txt");

        byte[] encryptedContent = encrypt(fileContent, initKeyWithEnc.getEncoded());
        writeFile("src/main/resources/outPut/encryptedFile.txt", encryptedContent);

        SecretKeyWithEncapsulation recKeyWithEnc = generateSecretKeyReceiver(keyPair.getPrivate(), encapsulation);
        byte[] decryptedContent = decrypt(encryptedContent, recKeyWithEnc.getEncoded());
        writeFile("src/main/resources/outPut/decryptedFile.txt", decryptedContent);


        endMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        endTime = System.nanoTime();

        memoryUsed = endMemory - startMemory;
        seconds = (endTime - startTime) / 1_000_000.0;
        memoryUsedInMGB = memoryUsed / (double)(1024 * 1024);

        System.out.println("Total execution time including AES: " + seconds + " ms");
        System.out.println("Total memory used including AES: " + memoryUsedInMGB + " megabytes");

        System.out.println("Shared Secret created by Sender: " + Hex.toHexString(initKeyWithEnc.getEncoded()));
        System.out.println("Shared Secret decapsulated by Receiver: " + Hex.toHexString(recKeyWithEnc.getEncoded()));

    }
}
