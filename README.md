Crypto
======

## RSA

## AES

## HMAC

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