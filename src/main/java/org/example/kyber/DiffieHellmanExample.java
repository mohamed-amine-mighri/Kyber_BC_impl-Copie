//package org.example.kyber;
//
///**
// * @author Amine_Mighri
// */
//
//import javax.crypto.KeyAgreement;
//import java.security.*;
//import java.security.spec.X509EncodedKeySpec;
//
//public class DiffieHellmanExample {
//
//    public static KeyPair generateKeyPair() throws Exception {
//        KeyPairGenerator kpairGen = KeyPairGenerator.getInstance("DH");
//        kpairGen.initialize(1024); // You can choose a different key size
//        return kpairGen.generateKeyPair();
//    }
//
//    public static PublicKey generatePublicKey(byte[] pubKeyEnc) throws Exception {
//        KeyFactory keyFac = KeyFactory.getInstance("DH");
//        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyEnc);
//        return keyFac.generatePublic(x509KeySpec);
//    }
//
//    public static byte[] generateSharedSecret(KeyPair kpair, PublicKey pubKey) throws Exception {
//        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
//        keyAgree.init(kpair.getPrivate());
//        keyAgree.doPhase(pubKey, true);
//        return keyAgree.generateSecret();
//    }
//
//    public static void main(String[] args) throws Exception {
//        // Alice's side
//        KeyPair aliceKpair = generateKeyPair();
//        byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();
//
//        // Bob's side
//        PublicKey alicePubKey = generatePublicKey(alicePubKeyEnc);
//        KeyPair bobKpair = generateKeyPair();
//        byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();
//
//        // Bob generates the shared secret
//        byte[] bobSharedSecret = generateSharedSecret(bobKpair, alicePubKey);
//
//        // Alice's side
//        PublicKey bobPubKey = generatePublicKey(bobPubKeyEnc);
//
//        // Alice generates the shared secret
//        byte[] aliceSharedSecret = generateSharedSecret(aliceKpair, bobPubKey);
//
//        // Ensure the shared secrets match
//        if (!MessageDigest.isEqual(aliceSharedSecret, bobSharedSecret)) {
//            throw new Exception("Shared secrets do not match!");
//        }
//
//        // The shared secret can now be used for encryption or other purposes
//        System.out.println("Shared secret: " + aliceSharedSecret);
//    }
//}
