package com.helmigandi.encryption;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class CryptoHelper {
    private static final String ALGORITHM_KEY = "AES";
    private static final String ALGORITHM_ENCRYPTION = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int AES_KEY_LENGTH = 256;

    @Value("${aes.encryption.key}")
    private String aesKeyString;
    private SecretKey secretKey;

    /**
     * Set Key from application.properties after starting.
     */
    @PostConstruct
    public void initialize() {
        secretKey = new SecretKeySpec(Base64.getDecoder().decode(aesKeyString), ALGORITHM_KEY);
    }

    /**
     * Create random key string.
     *
     * @return Base64 key String.
     * @throws NoSuchAlgorithmException When wrong algorithm.
     */
    public static String generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance(ALGORITHM_KEY);
        keygen.init(AES_KEY_LENGTH);
        SecretKey key = keygen.generateKey();
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Encrypt byte content or value. Content must be encoded first with Base64.
     *
     * @param plainContent content byte array want to encrypt.
     * @return encrypted content as a byte array.
     * @throws NoSuchPaddingException             if no padding found.
     * @throws NoSuchAlgorithmException           if no algorithm found.
     * @throws InvalidAlgorithmParameterException if wrong algorithm.
     * @throws InvalidKeyException                if wrong secret key.
     * @throws IllegalBlockSizeException          if something goes wrong when encrypted.
     * @throws BadPaddingException                if wrong padding.
     */
    public byte[] encrypt(byte[] plainContent) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] iv = generateIV();

        Cipher cipher = Cipher.getInstance(ALGORITHM_ENCRYPTION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] cipherText = cipher.doFinal(plainContent);

        // Store the encrypted message and IV so that we can use it during decryption
        return ByteBuffer.allocate(iv.length + cipherText.length)
                .put(iv)
                .put(cipherText)
                .array();
    }

    /**
     * Decrypt byte content or value. Content must be decoded first with Base64.
     *
     * @param encryptedContent content byte array want to decrypt.
     * @return decrypted content as a byte array.
     * @throws NoSuchAlgorithmException           if no algorithm found.
     * @throws NoSuchPaddingException             if no padding found.
     * @throws InvalidKeyException                if wrong secret key.
     * @throws InvalidAlgorithmParameterException if wrong algorithm.
     * @throws IllegalBlockSizeException          if something goes wrong when encrypted.
     * @throws BadPaddingException                if wrong padding.
     */
    public byte[] decrypt(byte[] encryptedContent) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        ByteBuffer bb = ByteBuffer.wrap(encryptedContent);
        byte[] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM_ENCRYPTION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);
        return cipher.doFinal(cipherText);
    }

    /**
     * The Initialization vector(IV) size we will use is 16 bytes, which is equivalent to 16 * 8 = 128 bits.
     * We will use SecureRandom class to initialize random bytes to Initialization Vector(IV).
     *
     * @return random IV as array of byte.
     */
    private byte[] generateIV() {
        byte[] nonce = new byte[IV_LENGTH_BYTE];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }
}
