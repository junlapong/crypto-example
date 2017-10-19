Crypto
======

## RSA

 - [RSA Public Key Cryptography in Java](http://codeartisan.blogspot.com/2009/05/public-key-cryptography-in-java.html)
 - [Load RSA public key from file](https://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file)
 - [Read RSA keys from PEM files in Java](https://www.txedo.com/blog/java-read-rsa-keys-pem-file/)
 - [Generate RSA keys and write to a PEM file in Java](https://www.txedo.com/blog/java-generate-rsa-keys-write-pem-file/)
 - [AES encryption](https://aesencryption.net/)
 
## AES

## HMAC

Reference: [Examples of creating base64 hashes using HMAC SHA256](https://www.jokecamp.com/blog/examples-of-creating-base64-hashes-using-hmac-sha256-in-different-languages/)

### Java
```java
package crypto.hmac;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import org.junit.Test;

public class HmacSHA256Test {

    private static final String HMACSHA256 = "HmacSHA256";

    @Test
    public void test() throws Exception {

        try {

            String message = "Message";
            String secret  = "s3cr3t";

            Mac sha256_HMAC = Mac.getInstance(HMACSHA256);
            SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), HMACSHA256);
            sha256_HMAC.init(secret_key);

            String hash = Base64.getEncoder().encodeToString(sha256_HMAC.doFinal(message.getBytes()));
            System.out.println(hash); // Oj5bqpLLNqCIuJZ5Mwgyno+cLYCInL+rSJVshHv+Sjc=
            System.out.println();
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}
```

### PHP

```php
<?php

$s = hash_hmac('sha256', 'Message', 's3cr3t', true);
echo base64_encode($s); // Oj5bqpLLNqCIuJZ5Mwgyno+cLYCInL+rSJVshHv+Sjc=
echo PHP_EOL;

// EOF

```