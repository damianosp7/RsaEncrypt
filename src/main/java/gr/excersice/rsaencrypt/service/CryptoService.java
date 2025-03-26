package gr.excersice.rsaencrypt.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import javax.crypto.Cipher;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

@Service
public class CryptoService {

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private static final String RSA = "RSA";
    private static final String RSA_ALGORITHM = "RSA";
    private static final String PRIVATE_KEY_FILE = "privateKey.pem";
    private static final String PUBLIC_KEY_FILE = "publicKey.pem";

    public CryptoService() throws Exception {
            generateAndSaveKeys();
    }

    // Step 1: Hash a secret with BCrypt
    public String hashSecret(String secret) {
        return passwordEncoder.encode(secret);
    }

    // Step 2: Encrypt the hashed secret using RSA
    public String encryptWithPublicKey(String hashedSecret) throws Exception {
        PublicKey publicKey = loadPublicKey();
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        System.out.println("Hashed Secret length: [" + hashedSecret.getBytes().length + "]");
        System.out.println("Hashed Secret: [" + hashedSecret + "]");
        byte[] encryptedBytes = cipher.doFinal(hashedSecret.getBytes(StandardCharsets.UTF_8));
        System.out.println("Encrypted Data length: [" + encryptedBytes.length + "]");
        System.out.println("Encrypted Data bytes: [" + encryptedBytes + "]");
        System.out.println("Encrypted Data: [" + Base64.getUrlEncoder().encodeToString(encryptedBytes) + "]");
        return Base64.getUrlEncoder().encodeToString(encryptedBytes);
    }

    // Step 3: Decrypt the encrypted hashed key using RSA private key
//    public String decryptWithPrivateKey(String encryptedData) throws Exception {
//        PrivateKey privateKey = loadPrivateKey();
//        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
//        cipher.init(Cipher.DECRYPT_MODE, privateKey);
//        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
//        return new String(decryptedBytes);
//    }

    public String decryptWithPrivateKey(String encryptedData) throws Exception {
        if (encryptedData == null || encryptedData.isEmpty()) {
            throw new IllegalArgumentException("Encrypted data cannot be null or empty.");
        }
        // Check if the length is a multiple of 4
        if (encryptedData.length() % 4 != 0) {
            throw new IllegalArgumentException("Base64 encoded string has invalid length.");
        }
        System.out.println("Encrypted Data: [" + encryptedData + "]");
        System.out.println("Length: " + encryptedData.length());
        try {
            PrivateKey privateKey = loadPrivateKey();
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            System.out.println("Encrypted Data: [" + encryptedData.trim() + "]");
            byte[] decryptedBytes = cipher.doFinal(Base64.getUrlDecoder().decode(encryptedData.trim()));
            System.out.println("Decrypted Data: [" + new String(decryptedBytes) + "]");
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Failed to decode Base64 encoded string: " + e.getMessage(), e);
        }
    }

    // RSA Key Pair Generation
    public void generateAndSaveKeys() throws Exception {
        File privateKeyFile = new File(PRIVATE_KEY_FILE);
        File publicKeyFile = new File(PUBLIC_KEY_FILE);

        if (!privateKeyFile.exists() || !publicKeyFile.exists()) {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            saveKeyToFile(PRIVATE_KEY_FILE, keyPair.getPrivate().getEncoded());
            saveKeyToFile(PUBLIC_KEY_FILE, keyPair.getPublic().getEncoded());
        }
    }

    private void saveKeyToFile(String fileName, byte[] keyBytes) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(keyBytes);
        }
    }

    private PublicKey loadPublicKey() throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(PUBLIC_KEY_FILE).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        return keyFactory.generatePublic(spec);
    }

    private PrivateKey loadPrivateKey() throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(PRIVATE_KEY_FILE).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        return keyFactory.generatePrivate(spec);
    }
}
