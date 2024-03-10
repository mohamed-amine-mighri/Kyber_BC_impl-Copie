package org.example.kyber;

/**
 * @author Amine_Mighri
 */

import javax.crypto.KeyAgreement;
import java.security.*;

public class DH {
    private static final int KEY_SIZE = 2048;

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(KEY_SIZE);
        return kpg.generateKeyPair();
    }

    public static byte[] generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(privateKey);
        ka.doPhase(publicKey, true);
        return ka.generateSecret();
    }

    public static void compareSharedSecrets(byte[] secretA, byte[] secretB) {
        if (java.util.Arrays.equals(secretA, secretB)) {
            System.out.println("Both parties have the same shared secret.");
        } else {
            System.out.println("The shared secrets are different.");
        }
    }
}
