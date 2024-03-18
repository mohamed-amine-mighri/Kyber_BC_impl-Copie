package senario;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.example.kyber.KyberExample;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

public class Server {
    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    private static final int PORT = 12345;

    public static void main(String[] args) throws Exception {
        KyberParameterSpec kyberParameterSpec = KyberParameterSpec.kyber512;
        KeyPair keyPair = KyberExample.generateKeyPair(kyberParameterSpec);
        PublicKey serverPublicKey = keyPair.getPublic();
        PrivateKey serverPrivateKey = keyPair.getPrivate();

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server is listening on port " + PORT);

            try (Socket socket = serverSocket.accept()) {
                System.out.println("Client connected");

// Sending public key to client
                try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                     ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
                    byte[] serverPublicKeyBytes = serverPublicKey.getEncoded(); // Encode public key
                    System.out.println("Server public key bytes: " +(serverPublicKeyBytes)); // Debugging
                    out.writeObject(serverPublicKeyBytes);
                    out.flush();

                    // Receive encrypted shared secret from client
                    byte[] clientEncapsulatedSecret = (byte[]) in.readObject();

                    // Decrypt and compute shared secret
                    SecretKeyWithEncapsulation sharedSecret = KyberExample.generateSecretKeyReceiver(serverPrivateKey, clientEncapsulatedSecret);
                    System.out.println("Shared secret computed");
                } catch (IOException | ClassNotFoundException e) {
                    e.printStackTrace();
                }

            }
        }
    }
}
