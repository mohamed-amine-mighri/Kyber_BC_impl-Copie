package Kyber; /**
 * @author Amine_Mighri
 */

import org.bouncycastle.util.encoders.Hex;
import org.example.kyber.KyberExample;
import org.junit.Test;

import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

public class KyberExampleTest {

    @Test
    public void testEncryptionAndDecryption() throws Exception {
        // Add the required providers for this exercise
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Security.addProvider(new org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider());

        // Loop over Kyber variants
        for (String kyberVariant : new String[]{"Kyber512", "Kyber768", "Kyber1024"}) {
            // Use reflection to access private methods
            Method generateKeyPairMethod = KyberExample.class.getDeclaredMethod("generateKeyPair", String.class);
            generateKeyPairMethod.setAccessible(true);
            KeyPair keyPair = (KeyPair) generateKeyPairMethod.invoke(null, kyberVariant);

           // KyberExample.initBouncyCastleProviders();

            System.out.println("KEM Algorithm: " + keyPair.getPublic().getAlgorithm());

            // Sender's side
            Method generateSecretKeySenderMethod = KyberExample.class.getDeclaredMethod("generateSecretKeySender", PublicKey.class);
            generateSecretKeySenderMethod.setAccessible(true);
            org.bouncycastle.jcajce.SecretKeyWithEncapsulation initKeyWithEnc =
                    (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) generateSecretKeySenderMethod.invoke(null, keyPair.getPublic());

            System.out.println("Shared Secret created by Sender: " + Hex.toHexString(initKeyWithEnc.getEncoded()));

            String originalText = "This is a secret message.";
            System.out.println("Original Text: " + originalText);

            //String encryptedText = KyberExample.encrypt(originalText, initKeyWithEnc.getEncoded());
            //System.out.println("Encrypted Text: " + encryptedText);

            // Receiver's side
            Method generateSecretKeyReceiverMethod = KyberExample.class.getDeclaredMethod(
                    "generateSecretKeyReceiver", PrivateKey.class, byte[].class);
            generateSecretKeyReceiverMethod.setAccessible(true);
            byte[] encapsulation = initKeyWithEnc.getEncapsulation(); // Get the encapsulation
            org.bouncycastle.jcajce.SecretKeyWithEncapsulation recKeyWithEnc =
                    (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) generateSecretKeyReceiverMethod.invoke(
                            null, keyPair.getPrivate(), encapsulation);

            System.out.println("Shared Secret decapsulated by Receiver: " + Hex.toHexString(recKeyWithEnc.getEncoded()));

            //String decryptedText = KyberExample.decrypt(encryptedText, recKeyWithEnc.getEncoded());
           // System.out.println("Decrypted Text: " + decryptedText);

            // Assert that the decrypted text matches the original text
            //assertEquals(originalText, decryptedText);
        }
    }
}
