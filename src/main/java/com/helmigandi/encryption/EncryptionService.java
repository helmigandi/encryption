package com.helmigandi.encryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;

@Service
public class EncryptionService {

    private final CryptoHelper cryptoHelper;

    @Value("classpath:profile.jpg")
    private Resource profilePicture;

    Logger logger = LoggerFactory.getLogger(EncryptionService.class);

    public EncryptionService(CryptoHelper cryptoHelper) {
        this.cryptoHelper = cryptoHelper;
    }

    public void test() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException,
            NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidParameterSpecException {
        BigDecimal balance = new BigDecimal("100000");
        logger.info("Balance: {}", balance);

        String encrypted = EncryptionUtil.encrypt(String.valueOf(balance));
        logger.info("Encrypted: {}", encrypted);

        String decrypt = EncryptionUtil.decrypt(encrypted);
        logger.info("Decrypt: {}", decrypt);
    }

    public void test2() {

        BigDecimal balance = new BigDecimal("451898578513791621.09");
        try {
            byte[] chiperText = cryptoHelper.encrypt(balance.toString().getBytes());
            String encrypted = Base64.getEncoder().encodeToString(chiperText);
            byte[] textBytes = cryptoHelper.decrypt(Base64.getDecoder().decode(encrypted.getBytes()));
            String decrypted = new String(textBytes);

            // File
//            Path path = Path.of("profile.jpg");
//            byte[] imageBytes = Files.readAllBytes(path);
//            Files.write(Path.of("profile-ecnrypt"), cryptoHelper.encrypt(imageBytes));
//            Path decryptPath = Path.of("profile-ecnrypt");
//            Files.write(Path.of("profile-decrypted.jpg"), cryptoHelper.decrypt(Files.readAllBytes(decryptPath)));

//            Path path = Path.of("text.txt");
//            byte[] imageBytes = Files.readAllBytes(path);
//            Files.write(Path.of("text-ecnrypted"), cryptoHelper.encrypt(imageBytes));
//            Path decryptPath = Path.of("text-ecnrypted");
//            byte[] decryptedText = cryptoHelper.decrypt(Files.readAllBytes(decryptPath));
//            Files.write(Path.of("text-decrypted.txt"), decryptedText);
//            String text = new String(decryptedText);
//            System.out.println(text);

            logger.info("Text before encrypt: {}", balance);
            logger.info("Text after encrypt: {}", encrypted);
            logger.info("Text after encrypt: {}", decrypted);

        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException |
                 NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
            logger.error(e.getMessage(), e);
        }
    }
}
