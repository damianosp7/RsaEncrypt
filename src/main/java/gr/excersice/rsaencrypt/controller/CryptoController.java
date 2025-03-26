package gr.excersice.rsaencrypt.controller;
import gr.excersice.rsaencrypt.service.CryptoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

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