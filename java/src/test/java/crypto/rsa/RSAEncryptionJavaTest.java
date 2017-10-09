package crypto.rsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Java example for RSA encryption/decryption.
// Uses Apache commons codec library
// Uses strong encryption with 2048 key size.
public class RSAEncryptionJavaTest {

    @Test
    public void test() throws Exception {

        String plainText = "Hello World!";

        // Generate public and private keys using RSA
        Map<String, Object> keys = getRSAKeys();

        PublicKey publicKey   = (PublicKey) keys.get("public");
        String encryptedText  = encryptMessage(plainText, publicKey);

        // ----- The following logic is on the other side ----- //

        PrivateKey privateKey = (PrivateKey) keys.get("private");
        String descryptedText = decryptMessage(encryptedText, privateKey);

        System.out.println("input     : " + plainText);
        System.out.println("encrypted : " + encryptedText);
        System.out.println("decrypted : " + descryptedText);
        System.out.println();

    }

    // Get RSA keys. Uses key size of 2048.
    private static Map<String, Object> getRSAKeys() throws Exception {

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

    public static String encryptMessage(String plainText, PublicKey publicKey) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return Base64.encodeBase64String(cipher.doFinal(plainText.getBytes()));
    }

    public static String decryptMessage(String encryptedText, PrivateKey privateKey) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(cipher.doFinal(Base64.decodeBase64(encryptedText)));
    }
}