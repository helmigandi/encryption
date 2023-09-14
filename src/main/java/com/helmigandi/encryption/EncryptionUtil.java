package com.helmigandi.encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Base64;

public class EncryptionUtil {

    private static final String KEY = "3q7#zoxN@R4E9X&i";

    private static final String ALGORITHM = "AES";

    public static final String CHIPER_MODE = "AES/CBC/PKCS5Padding";

    public static String encrypt(String plainText) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(CHIPER_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        System.out.println(Base64.getEncoder().encodeToString(cipher.getIV()));
        System.out.println(Base64.getEncoder().encodeToString(cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV()));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] encryptedData = Base64.getDecoder().decode(cipherText);
        byte[] iv = Arrays.copyOfRange(encryptedData, 0, 16); // Adjust size based on AES key size

        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(CHIPER_MODE);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decrypted = cipher.doFinal(encryptedData);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private static byte[] generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
