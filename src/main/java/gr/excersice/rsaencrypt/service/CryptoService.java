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

    /**
     * Hashes the given secret using BCrypt.
     * This method uses the BCryptPasswordEncoder to hash the provided secret.
     *
     * @param secret the secret to hash
     * @return the hashed secret as a string
     */
    public String hashSecret(String secret) {
        return passwordEncoder.encode(secret);
    }

    /**
     * Encrypts the given hashed secret using the RSA public key.
     *
     * This method performs the following steps:
     * 1. Loads the RSA public key from the file system.
     * 2. Initializes the Cipher instance for encryption using the RSA algorithm.
     * 3. Encrypts the hashed secret using the public key.
     * 4. Encodes the encrypted byte array to a Base64 encoded string and returns it.
     *
     * @param hashedSecret the hashed secret to encrypt
     * @return the encrypted data as a Base64 encoded string
     * @throws Exception if an error occurs during encryption
     */
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

    /**
     * Decrypts the given encrypted data using the RSA private key.
     *
     * This method performs the following steps:
     * 1. Validates the input encrypted data to ensure it is not null or empty.
     * 2. Checks if the length of the Base64 encoded string is a multiple of 4.
     * 3. Loads the RSA private key from the file system.
     * 4. Initializes the Cipher instance for decryption using the RSA algorithm.
     * 5. Decodes the Base64 encoded encrypted data and decrypts it using the private key.
     * 6. Converts the decrypted byte array to a UTF-8 encoded string and returns it.
     *
     * @param encryptedData the Base64 encoded encrypted data to decrypt
     * @return the decrypted data as a UTF-8 encoded string
     * @throws Exception if an error occurs during decryption or if the input data is invalid
     * @throws IllegalArgumentException if the encrypted data is null, empty, or has an invalid Base64 length
     */
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

    /**
     * Generates and saves RSA key pairs to files if they do not already exist.
     *
     * This method checks for the existence of the private and public key files.
     * If either file does not exist, it generates a new RSA key pair and saves
     * the private key to the private key file and the public key to the public key file.
     *
     * @throws Exception if an error occurs during key generation or file operations
     */
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

    /**
     * Saves the given key bytes to a file.
     *
     * @param fileName the name of the file to save the key to
     * @param keyBytes the key bytes to save
     * @throws Exception if an error occurs while writing the key to the file
     */
    private void saveKeyToFile(String fileName, byte[] keyBytes) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(keyBytes);
        }
    }

    /**
     * Loads the public key from a file.
     *
     * @return the public key
     * @throws Exception if an error occurs while reading the key file or generating the public key
     */
    private PublicKey loadPublicKey() throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(PUBLIC_KEY_FILE).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        return keyFactory.generatePublic(spec);
    }

    /**
     * Loads the private key from a file.
     *
     * @return the private key
     * @throws Exception if an error occurs while reading the key file or generating the private key
     */
    private PrivateKey loadPrivateKey() throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(PRIVATE_KEY_FILE).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        return keyFactory.generatePrivate(spec);
    }
}
