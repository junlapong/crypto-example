package crypto.rsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Java 8 example for RSA encryption/decryption.
// Uses strong encryption with 2048 key size.
public class RSAEncryptionJava8Test {

    @Test
    public void test() throws Exception {

        String plainText = "Hello World!";

        // Generate public and private keys using RSA
        Map<String, Object> keys = getRSAKeys();

        PublicKey publicKey  = (PublicKey) keys.get("public");
        String encryptedText = encryptMessage(plainText, publicKey);

        // ----- The following logic is on the other side ----- //

        PrivateKey privateKey = (PrivateKey) keys.get("private");
        String descryptedText = decryptMessage(encryptedText, privateKey);

        System.out.println("input     : " + plainText);
        System.out.println("encrypted : " + encryptedText);
        System.out.println("decrypted : " + descryptedText);
        System.out.println();

    }

    // Get RSA keys. Uses key size of 2048.
    private static Map<String,Object> getRSAKeys() throws Exception {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        KeyPair keyPair       = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey   = keyPair.getPublic();

        Map<String, Object> keys = new HashMap<String,Object>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);

        return keys;
    }

    // Encrypt using RSA private key
    public static String encryptMessage(String plainText, PublicKey publicKey) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }

    // Decrypt using RSA public key
    public static String decryptMessage(String encryptedText, PrivateKey privateKey) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));
    }

}