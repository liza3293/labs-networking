package com.example.lab7.service;

import com.example.lab7.model.RsaKeys;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

@Service
public class RsaService {

    public RsaKeys generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            String privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

            return new RsaKeys(publicKey, privateKey);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Помилка генерації ключів RSA", e);
        }
    }

    public String encrypt(String publicKey, String plainText) {
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey key = keyFactory.generatePublic(new java.security.spec.X509EncodedKeySpec(publicKeyBytes));

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Помилка шифрування RSA", e);
        }
    }

    public String decrypt(String privateKey, String cipherText) {
        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey key = keyFactory.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(privateKeyBytes));

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decodedBytes = Base64.getDecoder().decode(cipherText);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Помилка дешифрування RSA", e);
        }
    }
}