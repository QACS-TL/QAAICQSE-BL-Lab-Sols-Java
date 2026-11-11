package lab3.exemplar;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.mindrot.jbcrypt.BCrypt;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

final class PasswordHasher {
    private static final int ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;
    private static final String PREFIX = "pbkdf2-sha256$" + ITERATIONS + "$";
    private static final String BCRYPT_PREFIX = "bcrypt-sha256$";
    private static final int BCRYPT_COST = 12;
    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordHasher() {
    }

    static String hash(String password) {
        return BCRYPT_PREFIX + BCrypt.hashpw(prehash(password), BCrypt.gensalt(BCRYPT_COST, RANDOM));
    }

    static boolean matches(String password, String storedHash) {
        if ("!reset-required!".equals(storedHash)) {
            return false;
        }
        if (storedHash != null && storedHash.startsWith(BCRYPT_PREFIX)) {
            try {
                return BCrypt.checkpw(prehash(password), storedHash.substring(BCRYPT_PREFIX.length()));
            } catch (IllegalArgumentException exception) {
                throw new IllegalStateException("Invalid stored password hash", exception);
            }
        }
        if (storedHash == null || !storedHash.startsWith(PREFIX)) {
            throw new IllegalStateException("Unsupported stored password format");
        }
        String[] parts = storedHash.substring(PREFIX.length()).split("\\$", -1);
        if (parts.length != 2) {
            throw new IllegalStateException("Invalid stored password format");
        }
        byte[] salt;
        byte[] expected;
        try {
            salt = Base64.getDecoder().decode(parts[0]);
            expected = Base64.getDecoder().decode(parts[1]);
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException("Invalid stored password encoding", exception);
        }
        if (salt.length != SALT_BYTES || expected.length != HASH_BITS / 8) {
            throw new IllegalStateException("Invalid stored password salt or hash length");
        }
        return MessageDigest.isEqual(expected, derive(password, salt));
    }

    static boolean needsUpgrade(String storedHash) {
        return storedHash.startsWith(PREFIX);
    }

    private static String prehash(String password) {
        try {
            return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256")
                    .digest(password.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static byte[] derive(String password, byte[] salt) {
        PBEKeySpec specification = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, HASH_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(specification).getEncoded();
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Password hashing is unavailable", exception);
        } finally {
            specification.clearPassword();
        }
    }
}
