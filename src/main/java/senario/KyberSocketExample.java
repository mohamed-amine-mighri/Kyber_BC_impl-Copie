package senario;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.example.kyber.KyberExample;

import java.io.DataOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;

public class KyberSocketExample {

    public static void main(String[] args) {
        // Adding BouncyCastle PQC provider
        Security.addProvider(new BouncyCastlePQCProvider());

        // Server side
// Server side
        new Thread(() -> {
            try {
                ServerSocket serverSocket = new ServerSocket(9999);
                System.out.println("Server waiting for client...");
                Socket socket = serverSocket.accept();

                // Server generates key pair
                System.out.println("Server: Generating key pair...");
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Kyber", "BCPQC");
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                System.out.println("Server: Key pair generated successfully.");

                // Ensure keyPair and its PublicKey are not null before accessing
                if (keyPair != null && keyPair.getPublic() != null) {
                    byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
                    DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
                    dos.writeInt(publicKeyBytes.length);
                    dos.write(publicKeyBytes);
                    dos.flush();
                } else {
                    System.out.println("Server: Key pair or its public key is null.");
                }

                serverSocket.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();



        // Client side
        new Thread(() -> {
            try {
                Socket socket = new Socket("localhost", 9999);
                System.out.println("Client: Connected to server.");

                // Receive public key from server
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                System.out.println("Client: Receiving public key...");
                PublicKey publicKey = (PublicKey) in.readObject();
                System.out.println("Client: Public key received successfully.");

                // Generate shared secret using server's public key
                KyberExample kyber = new KyberExample();
                SecretKeyWithEncapsulation sharedSecret = kyber.generateSecretKeySender(publicKey);

                // Encrypt shared secret
                byte[] encryptedSharedSecret = sharedSecret.getEncoded();

                // Send encrypted shared secret to server
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                out.writeObject(encryptedSharedSecret);
                out.flush();

                System.out.println("Client: Shared secret sent successfully.");

                socket.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }
}
