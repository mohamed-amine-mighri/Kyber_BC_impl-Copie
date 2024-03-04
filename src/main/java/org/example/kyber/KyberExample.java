package org.example.kyber;

/**
 * @author Amine_Mighri
 */

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class KyberExample {
    private static final String KEM_ALGORITHM = "Kyber";
    private static final String PROVIDER = "BCPQC";
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String MODE_PADDING = "AES/ECB/PKCS5Padding";

    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

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

    public static KeyPair generateKeyPair(KyberParameterSpec kyberParameterSpec) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEM_ALGORITHM, PROVIDER);
        keyPairGenerator.initialize(kyberParameterSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static SecretKeyWithEncapsulation generateSecretKeySender(PublicKey publicKey) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEM_ALGORITHM, PROVIDER);
        KEMGenerateSpec kemGenerateSpec = new KEMGenerateSpec(publicKey, "Secret");
        keyGenerator.init(kemGenerateSpec);
        return (SecretKeyWithEncapsulation) keyGenerator.generateKey();
    }

    public static SecretKeyWithEncapsulation generateSecretKeyReceiver(PrivateKey privateKey, byte[] encapsulation) throws Exception {
        KEMExtractSpec kemExtractSpec = new KEMExtractSpec(privateKey, encapsulation, "Secret");
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEM_ALGORITHM, PROVIDER);
        keyGenerator.init(kemExtractSpec);
        return (SecretKeyWithEncapsulation) keyGenerator.generateKey();
    }


//    public static void main(String[] args) throws Exception {
//
//        // Let's add the required providers for this exercise
//        // the regular Bouncy Castle provider for ECDHC
//        Security.addProvider(new BouncyCastleProvider());
//        // the Bouncy Castle post quantum provider for the PQC KEM.
//        Security.addProvider(new BouncyCastlePQCProvider());
//
//        // Generating a key pair for receiver
//        //KeyPair keyPair = generateKeyPair();
//
//        System.out.println("KEM Algorithm: " + keyPair.getPublic().getAlgorithm());
//        //System.out.println("Public Key length: " + keyPair.getPublic().getEncoded().length);
//        //System.out.println("Private Key length: " + keyPair.getPrivate().getEncoded().length);
//
//        SecretKeyWithEncapsulation initKeyWithEnc = generateSecretKeySender(keyPair.getPublic());
//        byte[] encapsulation = initKeyWithEnc.getEncapsulation();
//
//        System.out.println("Shared Secret created by Sender: " + Hex.toHexString(initKeyWithEnc.getEncoded()));
//        System.out.println("Length of encapsulated shared secret: " + encapsulation.length);
//
//        String originalText = "This is a secret message.";
//        System.out.println("Original Text: " + originalText);
//
//        String encryptedText = encrypt(originalText, initKeyWithEnc.getEncoded());
//        System.out.println("Encrypted Text: " + encryptedText);
//
//
//        SecretKeyWithEncapsulation recKeyWithEnc = generateSecretKeyReceiver(keyPair.getPrivate(), encapsulation);
//
//        System.out.println("Shared Secret decapsulated by Receiver: " + Hex.toHexString(recKeyWithEnc.getEncoded()));
//
//        String decryptedText = decrypt(encryptedText, recKeyWithEnc.getEncoded());
//        System.out.println("Decrypted Text: " + decryptedText);
//    }
}