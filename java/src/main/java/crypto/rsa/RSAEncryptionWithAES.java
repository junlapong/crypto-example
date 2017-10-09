package crypto.rsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.MessageDigest;

import java.util.HashMap;
import java.util.Map;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.commons.codec.binary.Hex;

public class RSAEncryptionWithAES {

    // Encrypt text using AES key
    public static String encryptTextUsingAES(String plainText, String aesKey) throws Exception {

        byte[] decodedKey = Hex.decodeHex(aesKey.toLowerCase().toCharArray());
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        // AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, originalKey);
        byte[] byteCipherText = aesCipher.doFinal(plainText.getBytes());

        return Hex.encodeHexString(byteCipherText);
    }

    // Decrypt text using AES key
    public static String decryptTextUsingAES(String encryptedText, String aesKey) throws Exception {

        byte[] encryptTextBytes = Hex.decodeHex(encryptedText.toCharArray());
        byte[] encodedKey = Hex.decodeHex(aesKey.toLowerCase().toCharArray());
        SecretKey originalKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, originalKey);
        byte[] decyrptTextBytes = cipher.doFinal(encryptTextBytes);

        return new String(decyrptTextBytes);
    }

    // Encrypt AES Key using RSA public key
    public static String encryptAESKey(String plainAESKey, PublicKey publicKey) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return Base64.getEncoder().encodeToString(cipher.doFinal(plainAESKey.getBytes()));
    }

    // Decrypt AES Key using RSA private key
    public static String decryptAESKey(String encryptedAESKey, PrivateKey privateKey) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedAESKey)));
    }

    public static String getAesKey(String secretKey) throws Exception {

        byte[] key = secretKey.getBytes("UTF-8");
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        key = sha.digest(key);

        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        String aesKey = Hex.encodeHexString(secretKeySpec.getEncoded());

        return aesKey;
    }

    // Get RSA keys. Uses key size of 2048.
    public static Map<String, Object> getRSAKeys() throws Exception {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        KeyPair keyPair       = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey   = keyPair.getPublic();

        Map<String, Object> keys = new HashMap<String, Object>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
        
        return keys;
    }

}