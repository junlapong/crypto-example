package crypto;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import javax.crypto.Cipher;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple utility class to check if AES256 can be used by JVM.
 * 
 * @author jkaplan
 *
 */
public class AES256JavaCheckTest {

	private static final String JAVA_HOME = "java.home";
	private static final String JAVA_VERSION = "java.version";
	private static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";
	private static final String UNLIMITED_JCE_INSTALLED = "Unlimited JCE policy is active for JVM. JVM can use AES256.";
	private static final String UNLIMITED_JCE_NOT_INSTALLED = "Unlimited JCE policy has not been applied for JVM. JVM cannot use AES256.";

	@Test
	public void test() throws NoSuchAlgorithmException {

		String[] args = {"-v"};

		Set<String> argsSet = Arrays.stream(args).collect(Collectors.toSet());
		checkArgs(argsSet);

		int maxAesCipherSize = Cipher.getMaxAllowedKeyLength(AES_TRANSFORMATION);
		String message = maxAesCipherSize == Integer.MAX_VALUE ? UNLIMITED_JCE_INSTALLED : UNLIMITED_JCE_NOT_INSTALLED;
		
		System.out.println(">>> " + message);
	}

	private static void checkArgs(Set<String> argsSet) {
		if (argsSet.contains("-v") || argsSet.contains("--verbose")) {
			System.out.println(JAVA_HOME + " : " + System.getProperty(JAVA_HOME));
			System.out.println(JAVA_VERSION + " : " + System.getProperty(JAVA_VERSION));
			System.out.println();
		}
	}

}
