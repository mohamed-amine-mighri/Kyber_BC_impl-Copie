package senario;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.encoders.Hex;
import org.example.kyber.KyberExample;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.security.Security;

public class Client {
    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    private static final String SERVER_ADDRESS = "localhost";
    private static final int PORT = 12345;

    public static void main(String[] args) throws Exception {
        try (Socket socket = new Socket(SERVER_ADDRESS, PORT)) {
            System.out.println("Connected to server");

// Setup to receive server's public key
            try (ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                 ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())) {
                byte[] serverPublicKeyBytes = (byte[]) in.readObject();
                System.out.println("Received server public key bytes: " + Hex.toHexString(serverPublicKeyBytes)); // Debugging

                if (serverPublicKeyBytes != null) {
                    PublicKey serverPublicKey = (PublicKey) PublicKeyFactory.createKey(serverPublicKeyBytes);
                    if (serverPublicKey != null) {
                        // Generate shared secret and encapsulation
                        SecretKeyWithEncapsulation encapsulatedSecret = KyberExample.generateSecretKeySender(serverPublicKey);

                        // Send encapsulated secret to server
                        out.writeObject(encapsulatedSecret);
                        out.flush();

                        System.out.println("Encapsulated secret sent to server");
                    } else {
                        System.out.println("Failed to create public key from received bytes");
                    }
                } else {
                    System.out.println("Received server public key bytes are null");
                }
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }

        }
    }
}
