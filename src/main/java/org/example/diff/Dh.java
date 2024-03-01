package org.example.diff;

/**
 * @author Amine_Mighri
 */
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class Dh {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // Generate a key pair for Alice
        KeyPair aliceKeyPair = generateKeyPair();
        byte[] alicePubKeyEnc = aliceKeyPair.getPublic().getEncoded();

        // Generate a key pair for Bob using the same parameters
        KeyPair bobKeyPair = generateKeyPair(((DHPublicKey) aliceKeyPair.getPublic()).getParams());
        byte[] bobPubKeyEnc = bobKeyPair.getPublic().getEncoded();

        // Alice uses Bob's public key for the key agreement
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH", "BC");
        aliceKeyAgree.init(aliceKeyPair.getPrivate());
        KeyFactory aliceKeyFac = KeyFactory.getInstance("DH", "BC");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
        PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
        aliceKeyAgree.doPhase(bobPubKey, true);

        // Bob uses Alice's public key for the key agreement
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH", "BC");
        bobKeyAgree.init(bobKeyPair.getPrivate());
        KeyFactory bobKeyFac = KeyFactory.getInstance("DH", "BC");
        x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);
        PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);
        bobKeyAgree.doPhase(alicePubKey, true);

        // Generate the shared secret
        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
        byte[] bobSharedSecret = bobKeyAgree.generateSecret();

        System.out.println("Alice's shared secret: " + toHexString(aliceSharedSecret));
        System.out.println("Bob's shared secret: " + toHexString(bobSharedSecret));
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", "BC");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair generateKeyPair(DHParameterSpec params) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", "BC");
        keyPairGenerator.initialize(params);
        return keyPairGenerator.generateKeyPair();
    }

    public static String toHexString(byte[] array) {
        StringBuilder sb = new StringBuilder(array.length * 2);
        for (byte b : array) {
            int v = b & 0xff;
            if (v < 16) {
                sb.append('0');
            }
            sb.append(Integer.toHexString(v));
        }
        return sb.toString();
    }
}