package lab3.exemplar;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Date;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class UserManagerTest {
    private static final String SECRET = "unit-test-only-signing-key-not-for-production";
    private static final String EMAIL = "alice@example.com";
    private final List<String> codes = new ArrayList<>();
    private Connection connection;
    private UserManager manager;
    private boolean failDelivery;

    @BeforeEach
    void setUp() throws SQLException {
        connection = new UserManagerConfiguration().userDatabaseConnection("jdbc:sqlite::memory:");
        manager = new UserManager(connection, SECRET, (email, purpose, code) -> {
            if (failDelivery) {
                throw new IllegalStateException("mail unavailable");
            }
            codes.add(code);
        });
    }

    @AfterEach
    void close() throws SQLException {
        manager.close();
    }

    @Test
    void registrationRequiresEmailVerificationAndPreventsReplay() {
        manager.registerUser(EMAIL, "Alice");
        assertNull(manager.authenticateUser(EMAIL, "password-long"));
        String code = codes.get(0);
        assertEquals("Email verified", manager.verifyEmail(EMAIL, "password-long", code));
        assertNotNull(manager.authenticateUser(EMAIL, "password-long"));
        assertThrows(SecurityException.class, () -> manager.verifyEmail(EMAIL, "other-password", code));
    }

    @Test
    void preRegistrationCannotSetTheVictimsPassword() {
        manager.registerUser(EMAIL, "attacker");
        manager.registerUser("ALICE@example.com", "victim");
        assertEquals(1, codes.size());
        manager.verifyEmail(EMAIL, "victim-password", codes.get(0));
        assertNull(manager.authenticateUser(EMAIL, "attacker-password"));
        assertNotNull(manager.authenticateUser(EMAIL, "victim-password"));
        assertThrows(SecurityException.class, () -> manager.verifyEmail(EMAIL, "attacker-password", codes.get(0)));
    }

    @Test
    void recoveryRequiresSingleUseCodeAndRevokesOldAccessTokens() {
        manager.registerUser(EMAIL, "Alice");
        manager.verifyEmail(EMAIL, "original-password", codes.get(0));
        String token = (String) manager.authenticateUser(EMAIL, "original-password").get("token");
        manager.requestPasswordReset(EMAIL);
        String recoveryCode = codes.get(1);
        assertThrows(SecurityException.class,
                () -> manager.resetPassword(EMAIL, "new-password", "incorrect"));
        assertEquals("Password reset", manager.resetPassword(EMAIL, "new-password", recoveryCode));
        assertThrows(SecurityException.class,
                () -> manager.resetPassword(EMAIL, "another-password", recoveryCode));
        assertNull(manager.authenticateUser(EMAIL, "original-password"));
        assertNotNull(manager.authenticateUser(EMAIL, "new-password"));
        assertThrows(SecurityException.class, () -> manager.getUserDataForToken("1", token));
    }

    @Test
    void tokenIsBoundToUserId() {
        manager.registerUser(EMAIL, "Alice");
        manager.verifyEmail(EMAIL, "password-long", codes.get(0));
        String token = (String) manager.authenticateUser(EMAIL, "password-long").get("token");
        assertEquals(EMAIL, manager.getUserDataForToken("1", token).get("email"));
        assertThrows(SecurityException.class, () -> manager.getUserDataForToken("2", token));
        assertEquals("1", JWT.require(Algorithm.HMAC256(SECRET)).build().verify(token).getSubject());
    }

    @Test
    void expiredCodeIsRejected() throws SQLException {
        manager.registerUser(EMAIL, "Alice");
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate("UPDATE email_codes SET expires_at = 0");
        }
        assertThrows(SecurityException.class, () -> manager.verifyEmail(EMAIL, "password-long", codes.get(0)));
    }

    @Test
    void codesAreStoredHashedAndBoundToTheirPurpose() throws SQLException {
        manager.registerUser(EMAIL, "Alice");
        String verificationCode = codes.get(0);
        try (Statement statement = connection.createStatement();
                java.sql.ResultSet result = statement.executeQuery("SELECT code_hash FROM email_codes")) {
            assertTrue(result.next());
            assertNotEquals(verificationCode, result.getString(1));
            assertEquals(64, result.getString(1).length());
        }
        assertThrows(SecurityException.class,
                () -> manager.resetPassword(EMAIL, "password-long", verificationCode));
        manager.verifyEmail(EMAIL, "password-long", verificationCode);
    }

    @Test
    void tokenCannotAccessAnotherUsersData() {
        manager.registerUser(EMAIL, "Alice");
        manager.verifyEmail(EMAIL, "alice-password", codes.get(0));
        String token = (String) manager.authenticateUser(EMAIL, "alice-password").get("token");
        manager.registerUser("bob@example.com", "Bob");
        manager.verifyEmail("bob@example.com", "bob-password", codes.get(1));
        assertThrows(SecurityException.class, () -> manager.getUserDataForToken("2", token));
    }

    @Test
    void forgedAndOldEmailOnlyTokensCannotAccessAccounts() {
        manager.registerUser(EMAIL, "Alice");
        manager.verifyEmail(EMAIL, "password-long", codes.get(0));
        String oldToken = JWT.create().withClaim("email", EMAIL)
                .withExpiresAt(new Date(System.currentTimeMillis() + 60_000))
                .sign(Algorithm.HMAC256(SECRET));
        String forgedToken = JWT.create().withSubject("1").withClaim("version", 1)
                .withExpiresAt(new Date(System.currentTimeMillis() + 60_000))
                .sign(Algorithm.HMAC256("secret123"));
        assertThrows(JWTVerificationException.class, () -> manager.getUserDataForToken("1", oldToken));
        assertThrows(JWTVerificationException.class, () -> manager.getUserDataForToken("1", forgedToken));
    }

    @Test
    void recoveryOfLegacyAccountRequiresEmailCode() throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO users (email, password, info) VALUES (?, ?, ?)")) {
            statement.setString(1, EMAIL);
            statement.setString(2, "!reset-required!");
            statement.setString(3, "Legacy");
            statement.executeUpdate();
        }
        assertNull(manager.authenticateUser(EMAIL, "password"));
        manager.requestPasswordReset(EMAIL);
        assertEquals("Password reset", manager.resetPassword(EMAIL, "new-password", codes.get(0)));
        assertNotNull(manager.authenticateUser(EMAIL, "new-password"));
    }

    @Test
    void sendingFailureIsReportedAndAllowsRetry() {
        failDelivery = true;
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> manager.registerUser(EMAIL, "Alice"));
        assertEquals("mail unavailable", exception.getMessage());
        failDelivery = false;
        manager.registerUser(EMAIL, "Alice");
        assertEquals(1, codes.size());
    }

    @Test
    void unknownRecoveryDoesNotSendEmail() {
        assertEquals("If the account exists, a recovery code has been sent",
                manager.requestPasswordReset(EMAIL));
        assertTrue(codes.isEmpty());
    }

    @Test
    void passwordHashUsesUniqueSalts() {
        String first = PasswordHasher.hash("password");
        String second = PasswordHasher.hash("password");
        assertNotEquals(first, second);
        assertTrue(PasswordHasher.matches("password", first));
        assertFalse(PasswordHasher.matches("wrong", first));
        assertFalse(PasswordHasher.matches("password", "!reset-required!"));
    }

    @Test
    void bcryptPrehashDoesNotTruncateLongPasswords() {
        String prefix = "a".repeat(72);
        String hash = PasswordHasher.hash(prefix + "first");
        assertTrue(PasswordHasher.matches(prefix + "first", hash));
        assertFalse(PasswordHasher.matches(prefix + "second", hash));
    }

    @Test
    void tokenMustHaveExpectedIssuerAudienceAndExpiration() {
        manager.registerUser(EMAIL, "Alice");
        manager.verifyEmail(EMAIL, "password-long", codes.get(0));
        String missingExpiration = JWT.create().withIssuer("user-manager").withAudience("user-api")
                .withSubject("1").withClaim("version", 1).sign(Algorithm.HMAC256(SECRET));
        String expired = JWT.create().withIssuer("user-manager").withAudience("user-api")
                .withSubject("1").withClaim("version", 1)
                .withExpiresAt(new Date(System.currentTimeMillis() - 60_000))
                .sign(Algorithm.HMAC256(SECRET));
        String wrongAudience = JWT.create().withIssuer("user-manager").withAudience("another-api")
                .withSubject("1").withClaim("version", 1)
                .withExpiresAt(new Date(System.currentTimeMillis() + 60_000))
                .sign(Algorithm.HMAC256(SECRET));
        assertThrows(SecurityException.class, () -> manager.getUserDataForToken("1", missingExpiration));
        assertThrows(JWTVerificationException.class, () -> manager.getUserDataForToken("1", expired));
        assertThrows(JWTVerificationException.class, () -> manager.getUserDataForToken("1", wrongAudience));
    }

    @Test
    void secretMustContainAtLeast32Bytes() {
        assertThrows(IllegalArgumentException.class,
                () -> new UserManager(connection, "short", (email, purpose, code) -> { }));
    }

    @Test
    void accountLockIsSharedBetweenIpsAndExpires() throws SQLException {
        manager.registerUser(EMAIL, "Alice");
        manager.verifyEmail(EMAIL, "password-long", codes.get(0));
        for (int i = 0; i < 5; i++) {
            assertNull(manager.authenticateUser(EMAIL, "wrong-password", "ip-" + i));
        }
        assertThrows(RateLimitException.class,
                () -> manager.authenticateUser(EMAIL, "password-long", "another-ip"));
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate("UPDATE authentication_limits SET expires_at = 0 WHERE scope = 'account'");
        }
        assertNotNull(manager.authenticateUser(EMAIL, "password-long", "another-ip"));
    }

    @Test
    void ipLimitAppliesAcrossAccountsIncludingUnknownOnes() {
        for (int i = 0; i < 30; i++) {
            assertNull(manager.authenticateUser("user" + i + "@example.com", "wrong", "same-ip"));
        }
        assertThrows(RateLimitException.class,
                () -> manager.authenticateUser("another@example.com", "wrong", "same-ip"));
        assertNull(manager.authenticateUser("another@example.com", "wrong", "other-ip"));
    }

    @Test
    void accountFailuresClearAfterSuccessfulLogin() {
        manager.registerUser(EMAIL, "Alice");
        manager.verifyEmail(EMAIL, "password-long", codes.get(0));
        for (int i = 0; i < 4; i++) {
            assertNull(manager.authenticateUser(EMAIL, "wrong", "ip"));
        }
        assertNotNull(manager.authenticateUser(EMAIL, "password-long", "ip"));
        for (int i = 0; i < 4; i++) {
            assertNull(manager.authenticateUser(EMAIL, "wrong", "ip"));
        }
        assertNotNull(manager.authenticateUser(EMAIL, "password-long", "ip"));
    }

    @Test
    void limitsSurviveNewManagerAndConnection(@TempDir Path temp) throws SQLException {
        String url = "jdbc:sqlite:" + temp.resolve("limits.db");
        try (Connection first = new UserManagerConfiguration().userDatabaseConnection(url);
                Connection second = new UserManagerConfiguration().userDatabaseConnection(url);
                UserManager firstManager = new UserManager(first, SECRET, (email, purpose, code) -> { });
                UserManager secondManager = new UserManager(second, SECRET, (email, purpose, code) -> { })) {
            for (int i = 0; i < 5; i++) {
                assertNull(firstManager.authenticateUser(EMAIL, "wrong", "ip"));
            }
            assertThrows(RateLimitException.class, () -> secondManager.authenticateUser(EMAIL, "wrong", "ip2"));
        }
    }

    @Test
    void concurrentInstancesCannotExceedAccountLimit(@TempDir Path temp) throws Exception {
        String url = "jdbc:sqlite:" + temp.resolve("concurrent.db");
        try (Connection first = new UserManagerConfiguration().userDatabaseConnection(url);
                Connection second = new UserManagerConfiguration().userDatabaseConnection(url);
                UserManager firstManager = new UserManager(first, SECRET, (email, purpose, code) -> { });
                UserManager secondManager = new UserManager(second, SECRET, (email, purpose, code) -> { })) {
            for (int i = 0; i < 4; i++) {
                assertNull(firstManager.authenticateUser(EMAIL, "wrong", "ip1"));
            }
            ExecutorService pool = Executors.newFixedThreadPool(2);
            try {
                CountDownLatch start = new CountDownLatch(1);
                Future<Boolean> firstResult = pool.submit(() -> tryLogin(firstManager, "ip1", start));
                Future<Boolean> secondResult = pool.submit(() -> tryLogin(secondManager, "ip2", start));
                start.countDown();
                assertNotEquals(firstResult.get(), secondResult.get());
            } finally {
                pool.shutdownNow();
            }
        }
    }

    @Test
    void inFlightAttemptCountsAgainstSharedAccountLimit(@TempDir Path temp) throws Exception {
        String url = "jdbc:sqlite:" + temp.resolve("reservations.db");
        CountDownLatch verifying = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        List<String> sentCodes = new ArrayList<>();
        try (Connection first = new UserManagerConfiguration().userDatabaseConnection(url);
                Connection second = new UserManagerConfiguration().userDatabaseConnection(url);
                UserManager firstManager = new UserManager(first, SECRET,
                        (email, purpose, code) -> sentCodes.add(code));
                UserManager secondManager = new UserManager(second, SECRET, (email, purpose, code) -> { },
                        (password, hash) -> {
                            verifying.countDown();
                            awaitRelease(release);
                            return PasswordHasher.matches(password, hash);
                        })) {
            firstManager.registerUser(EMAIL, "Alice");
            firstManager.verifyEmail(EMAIL, "password-long", sentCodes.get(0));
            for (int i = 0; i < 4; i++) {
                assertNull(firstManager.authenticateUser(EMAIL, "wrong", "ip1"));
            }
            ExecutorService pool = Executors.newSingleThreadExecutor();
            try {
                Future<Map<String, Object>> pending = pool.submit(
                        () -> secondManager.authenticateUser(EMAIL, "password-long", "ip2"));
                assertTrue(verifying.await(10, TimeUnit.SECONDS));
                assertThrows(RateLimitException.class,
                        () -> firstManager.authenticateUser(EMAIL, "password-long", "ip3"));
                release.countDown();
                assertNotNull(pending.get(10, TimeUnit.SECONDS));
                assertNotNull(firstManager.authenticateUser(EMAIL, "password-long", "ip3"));
            } finally {
                release.countDown();
                pool.shutdownNow();
            }
        }
    }

    @Test
    void passwordResetDuringVerificationCannotIssueOldToken(@TempDir Path temp) throws Exception {
        String url = "jdbc:sqlite:" + temp.resolve("reset-race.db");
        CountDownLatch verified = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        List<String> sentCodes = new ArrayList<>();
        try (Connection first = new UserManagerConfiguration().userDatabaseConnection(url);
                Connection second = new UserManagerConfiguration().userDatabaseConnection(url);
                UserManager firstManager = new UserManager(first, SECRET,
                        (email, purpose, code) -> sentCodes.add(code));
                UserManager secondManager = new UserManager(second, SECRET, (email, purpose, code) -> { },
                        (password, hash) -> {
                            boolean matches = PasswordHasher.matches(password, hash);
                            verified.countDown();
                            awaitRelease(release);
                            return matches;
                        })) {
            firstManager.registerUser(EMAIL, "Alice");
            firstManager.verifyEmail(EMAIL, "original-password", sentCodes.get(0));
            ExecutorService pool = Executors.newSingleThreadExecutor();
            try {
                Future<Map<String, Object>> pending = pool.submit(
                        () -> secondManager.authenticateUser(EMAIL, "original-password", "ip2"));
                assertTrue(verified.await(10, TimeUnit.SECONDS));
                firstManager.requestPasswordReset(EMAIL);
                firstManager.resetPassword(EMAIL, "new-password", sentCodes.get(1));
                release.countDown();
                assertNull(pending.get(10, TimeUnit.SECONDS));
                assertNotNull(firstManager.authenticateUser(EMAIL, "new-password", "ip1"));
            } finally {
                release.countDown();
                pool.shutdownNow();
            }
        }
    }

    @Test
    void successDoesNotEraseAnotherInFlightAttempt(@TempDir Path temp) throws Exception {
        String url = "jdbc:sqlite:" + temp.resolve("success-race.db");
        CountDownLatch verifying = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        List<String> sentCodes = new ArrayList<>();
        try (Connection first = new UserManagerConfiguration().userDatabaseConnection(url);
                Connection second = new UserManagerConfiguration().userDatabaseConnection(url);
                UserManager firstManager = new UserManager(first, SECRET,
                        (email, purpose, code) -> sentCodes.add(code));
                UserManager secondManager = new UserManager(second, SECRET, (email, purpose, code) -> { },
                        (password, hash) -> {
                            verifying.countDown();
                            awaitRelease(release);
                            return PasswordHasher.matches(password, hash);
                        })) {
            firstManager.registerUser(EMAIL, "Alice");
            firstManager.verifyEmail(EMAIL, "password-long", sentCodes.get(0));
            ExecutorService pool = Executors.newSingleThreadExecutor();
            try {
                Future<Map<String, Object>> pending = pool.submit(
                        () -> secondManager.authenticateUser(EMAIL, "wrong", "ip2"));
                assertTrue(verifying.await(10, TimeUnit.SECONDS));
                assertNotNull(firstManager.authenticateUser(EMAIL, "password-long", "ip1"));
                for (int i = 0; i < 4; i++) {
                    assertNull(firstManager.authenticateUser(EMAIL, "wrong", "ip1"));
                }
                assertThrows(RateLimitException.class,
                        () -> firstManager.authenticateUser(EMAIL, "password-long", "ip1"));
                release.countDown();
                assertNull(pending.get(10, TimeUnit.SECONDS));
                assertThrows(RateLimitException.class,
                        () -> firstManager.authenticateUser(EMAIL, "password-long", "ip1"));
            } finally {
                release.countDown();
                pool.shutdownNow();
            }
        }
    }

    @Test
    void failedVerificationKeepsReservationUntilItExpires() throws SQLException {
        manager.registerUser(EMAIL, "Alice");
        manager.verifyEmail(EMAIL, "password-long", codes.get(0));
        try (UserManager failing = new UserManager(connection, SECRET, (email, purpose, code) -> { },
                (password, hash) -> { throw new IllegalStateException("verification failed"); })) {
            assertThrows(IllegalStateException.class, () -> failing.authenticateUser(EMAIL, "password-long", "ip1"));
            for (int i = 0; i < 4; i++) {
                assertNull(manager.authenticateUser(EMAIL, "wrong", "ip1"));
            }
            assertThrows(RateLimitException.class, () -> manager.authenticateUser(EMAIL, "password-long", "ip1"));
            try (Statement statement = connection.createStatement()) {
                statement.executeUpdate("UPDATE authentication_reservations SET expires_at = 0");
            }
            assertNotNull(manager.authenticateUser(EMAIL, "password-long", "ip1"));
        }
    }

    @Test
    void simultaneousLegacyLoginsBothSucceedAndUpgrade(@TempDir Path temp) throws Exception {
        String url = "jdbc:sqlite:" + temp.resolve("legacy-race.db");
        CountDownLatch verifying = new CountDownLatch(2);
        CountDownLatch release = new CountDownLatch(1);
        java.util.function.BiPredicate<String, String> verifier = (password, hash) -> {
            verifying.countDown();
            awaitRelease(release);
            return PasswordHasher.matches(password, hash);
        };
        try (Connection first = new UserManagerConfiguration().userDatabaseConnection(url);
                Connection second = new UserManagerConfiguration().userDatabaseConnection(url);
                UserManager firstManager = new UserManager(first, SECRET, (email, purpose, code) -> { }, verifier);
                UserManager secondManager = new UserManager(second, SECRET, (email, purpose, code) -> { }, verifier)) {
            byte[] salt = new byte[16];
            PBEKeySpec spec = new PBEKeySpec("password-long".toCharArray(), salt, 600_000, 256);
            byte[] hash = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            spec.clearPassword();
            String legacy = "pbkdf2-sha256$600000$" + Base64.getEncoder().encodeToString(salt)
                    + "$" + Base64.getEncoder().encodeToString(hash);
            try (PreparedStatement insert = first.prepareStatement(
                    "INSERT INTO users (email, password, info, email_verified) VALUES (?, ?, ?, 1)")) {
                insert.setString(1, EMAIL);
                insert.setString(2, legacy);
                insert.setString(3, "Alice");
                insert.executeUpdate();
            }
            ExecutorService pool = Executors.newFixedThreadPool(2);
            try {
                Future<Map<String, Object>> one = pool.submit(
                        () -> firstManager.authenticateUser(EMAIL, "password-long", "ip1"));
                Future<Map<String, Object>> two = pool.submit(
                        () -> secondManager.authenticateUser(EMAIL, "password-long", "ip2"));
                assertTrue(verifying.await(10, TimeUnit.SECONDS));
                release.countDown();
                assertNotNull(one.get(15, TimeUnit.SECONDS));
                assertNotNull(two.get(15, TimeUnit.SECONDS));
                try (Statement statement = first.createStatement();
                        java.sql.ResultSet result = statement.executeQuery("SELECT password FROM users")) {
                    assertTrue(result.next());
                    assertTrue(result.getString(1).startsWith("bcrypt-sha256$"));
                }
            } finally {
                release.countDown();
                pool.shutdownNow();
            }
        }
    }

    private static void awaitRelease(CountDownLatch release) {
        try {
            if (!release.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting for verification release");
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Verification interrupted", exception);
        }
    }

    private static boolean tryLogin(UserManager manager, String ip, CountDownLatch start) throws InterruptedException {
        start.await();
        try {
            manager.authenticateUser(EMAIL, "wrong", ip);
            return true;
        } catch (RateLimitException expected) {
            return false;
        }
    }

    @Test
    void legacyPbkdf2HashIsUpgradedOnLogin() throws Exception {
        byte[] salt = new byte[16];
        PBEKeySpec spec = new PBEKeySpec("password-long".toCharArray(), salt, 600_000, 256);
        byte[] hash = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        spec.clearPassword();
        String legacy = "pbkdf2-sha256$600000$" + Base64.getEncoder().encodeToString(salt)
                + "$" + Base64.getEncoder().encodeToString(hash);
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO users (email, password, info, email_verified) VALUES (?, ?, ?, 1)")) {
            statement.setString(1, EMAIL);
            statement.setString(2, legacy);
            statement.setString(3, "Alice");
            statement.executeUpdate();
        }
        assertNotNull(manager.authenticateUser(EMAIL, "password-long"));
        try (Statement statement = connection.createStatement();
                java.sql.ResultSet result = statement.executeQuery("SELECT password FROM users")) {
            assertTrue(result.next());
            assertTrue(result.getString(1).startsWith("bcrypt-sha256$"));
        }
    }

    @Test
    void validatesNewPasswordsAndRejectsSqlInjection() {
        manager.registerUser(EMAIL, "Alice");
        assertThrows(IllegalArgumentException.class, () -> manager.verifyEmail(EMAIL, "short", codes.get(0)));
        assertThrows(IllegalArgumentException.class, () -> manager.registerUser("x' OR 1=1 --", "x"));
        assertThrows(IllegalArgumentException.class, () -> manager.registerUser("x@example.com", "line\nbreak"));
        manager.verifyEmail(EMAIL, "password-long", codes.get(0));
    }
}
