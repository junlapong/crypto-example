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

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.commons.codec.binary.Hex;

import static crypto.rsa.RSAEncryptionWithAES.*;

// Java 8 example for RSA-AES encryption/decryption.
// Uses strong encryption with 2048 key size.
public class RSAEncryptionWithAESTest {

    @Test
    public void test() throws Exception {
        
        String plainText = "Hello World!";

        // Generate public and private keys using RSA
        Map<String, Object> keys = getRSAKeys();

        PublicKey publicKey = (PublicKey) keys.get("public");

        // First create an AES Key
        String aesKey = getAesKey("s3cr3t-k3y");

        // Encrypt our data with AES key
        String encryptedText = encryptTextUsingAES(plainText, aesKey);

        // Encrypt AES Key with RSA Public Key
        String encryptedAESKeyString = encryptAESKey(aesKey, publicKey);


        // ----- The following logic is on the other side ----- //


        PrivateKey privateKey = (PrivateKey) keys.get("private");

        // First decrypt the AES Key with RSA Private key
        String decryptedAESKeyString = decryptAESKey(encryptedAESKeyString, privateKey);

        // Now decrypt data using the decrypted AES key!
        String decryptedText = decryptTextUsingAES(encryptedText, decryptedAESKeyString);

        System.out.println("input     : " + plainText);
        System.out.println("AES Key   : " + aesKey);
        System.out.println("decrypted : " + decryptedText);
        System.out.println();

    }
}