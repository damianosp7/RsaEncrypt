package gr.excersice.rsaencrypt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(exclude = {
        org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class})
public class RsaEncryptApplication {

    public static void main(String[] args) {
        SpringApplication.run(RsaEncryptApplication.class, args);
    }

}
