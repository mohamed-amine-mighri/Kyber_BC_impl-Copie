//package diffieHellmanTests.diffTest;
//
///**
// * @author Amine_Mighri
// */
//
//import org.example.diff.Dh;
//import org.example.diff.DiffieHellman;
//import org.junit.Test;
//
//import java.security.KeyPair;
//import java.security.Security;
//import java.security.KeyPairGenerator;
//import java.security.spec.ECGenParameterSpec;
//
//
//public class ECDH_BCTest {
//
//    @Test
//    public void testKeyPairGenerationAndSecretKeyDerivation() {
//        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
//        Dh ecdhBc = new Dh();
//
//        long startKeyPairGenerationTime = System.currentTimeMillis();
//        try {
//            KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDH", "BC");
//            kpgen.initialize(new ECGenParameterSpec("secp192r1"));
//            KeyPair pairA = kpgen.generateKeyPair();
//            KeyPair pairB = kpgen.generateKeyPair();
//            long endKeyPairGenerationTime = System.currentTimeMillis();
//
//            long startSecretKeyDerivationTime = System.currentTimeMillis();
//            ecdhBc.doECDH("Alice's secret: ", DiffieHellman.savePrivateKey(pairA.getPrivate()), DiffieHellman.savePublicKey(pairB.getPublic()));
//            ecdhBc.doECDH("Bob's secret:   ", DiffieHellman.savePrivateKey(pairB.getPrivate()), DiffieHellman.savePublicKey(pairA.getPublic()));
//            long endSecretKeyDerivationTime = System.currentTimeMillis();
//
//            long keyPairGenerationTime = endKeyPairGenerationTime - startKeyPairGenerationTime;
//            long secretKeyDerivationTime = endSecretKeyDerivationTime - startSecretKeyDerivationTime;
//
//            System.out.println("Key Pair Generation Time: " + keyPairGenerationTime + " ms");
//            System.out.println("Secret Key Derivation Time: " + secretKeyDerivationTime + " ms");
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//}