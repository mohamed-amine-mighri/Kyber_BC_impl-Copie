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

public class KyberAlgo {

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

    // Utility methods for file handling (readFileFromResources and writeFile) remain the same

    // Main method implementation can be modified or used as per the specific use case
}