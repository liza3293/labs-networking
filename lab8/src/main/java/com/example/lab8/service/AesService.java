// Файл: src/main/java/com/example/lab8/service/AesService.java
// Додано метод generateKey() для сумісності з CryptoController з попередньої лабки

package com.example.lab8.service;

import com.example.lab8.model.AesKey;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class AesService {

    public AesKey generateKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            SecretKey secretKey = keyGenerator.generateKey();

            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);

            String keyBase64 = Base64.getEncoder().encodeToString(secretKey.getEncoded());
            String ivBase64 = Base64.getEncoder().encodeToString(iv);

            return new AesKey(keyBase64, ivBase64);
        } catch (Exception e) {
            throw new RuntimeException("Помилка генерації ключа AES", e);
        }
    }

    public String encrypt(AesKey aesKey, String plainText) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(aesKey.getKey());
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(Base64.getDecoder().decode(aesKey.getIv()));

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Помилка шифрування AES", e);
        }
    }

    public String decrypt(AesKey aesKey, String cipherText) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(aesKey.getKey());
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(Base64.getDecoder().decode(aesKey.getIv()));

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
            byte[] decodedBytes = Base64.getDecoder().decode(cipherText);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes, "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException("Помилка дешифрування AES", e);
        }
    }
}