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
            System.out.println(hash);
            System.out.println();
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}