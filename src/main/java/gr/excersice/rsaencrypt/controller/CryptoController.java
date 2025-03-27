package gr.excersice.rsaencrypt.controller;
import gr.excersice.rsaencrypt.service.CryptoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/crypto")
public class CryptoController {

    private final CryptoService cryptoService;

    @Autowired
    public CryptoController(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    // Hash a secret using BCrypt
    @PostMapping("/hash")
    public String hashSecret(@RequestParam String secret) {
        return cryptoService.hashSecret(secret);
    }

    // Encrypt the hashed secret using RSA
    @PostMapping("/encrypt")
    public String encrypt(@RequestParam String hashedSecret) throws Exception {
        return cryptoService.encryptWithPublicKey(hashedSecret);
    }

    // Encrypt the hashed secret using RSA from a JSON body because the hashed set looses information when passed as a query parameter (&,%, etc)
    // for example bcrypt hashes contain special characters that are lost when passed as query parameters
    @PostMapping("/encryptJsonBody")
    public String encryptJsonBody(@RequestBody Map<String, Object> requestBody) throws Exception {
        String hashedSecret = (String) requestBody.get("hashedSecret");
        return cryptoService.encryptWithPublicKey(hashedSecret);
    }

    // Decrypt the encrypted hashed key using RSA
    @PostMapping("/decrypt")
    public String decrypt(@RequestParam String encryptedData) throws Exception {
        return cryptoService.decryptWithPrivateKey(encryptedData);
    }

    // A simple GET method that returns a welcome message
    @GetMapping("/welcome")
    public String getWelcomeMessage() {
        return "Welcome to Spring Boot!";
    }
}