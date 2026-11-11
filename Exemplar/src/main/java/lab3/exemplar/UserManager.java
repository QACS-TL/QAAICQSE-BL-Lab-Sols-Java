package lab3.exemplar;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.Date;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Semaphore;
import java.util.function.BiPredicate;

public class UserManager implements AutoCloseable {
    private static final long LIMIT_WINDOW_MS = 15 * 60 * 1000L;
    private static final int ACCOUNT_FAILURE_LIMIT = 5;
    private static final int IP_ATTEMPT_LIMIT = 30;
    private final Connection connection;
    private final String secretKey;
    private final EmailSender emailSender;
    private final Semaphore passwordChecks = new Semaphore(Math.max(1, Runtime.getRuntime().availableProcessors()));
    private final BiPredicate<String, String> passwordVerifier;
    private static final SecureRandom RANDOM = new SecureRandom();

    public UserManager(Connection connection, String secretKey, EmailSender emailSender) {
        this(connection, secretKey, emailSender, PasswordHasher::matches);
    }

    UserManager(Connection connection, String secretKey, EmailSender emailSender,
            BiPredicate<String, String> passwordVerifier) {
        this.secretKey = requireSecret(secretKey);
        this.connection = java.util.Objects.requireNonNull(connection, "connection");
        this.emailSender = java.util.Objects.requireNonNull(emailSender, "emailSender");
        this.passwordVerifier = java.util.Objects.requireNonNull(passwordVerifier, "passwordVerifier");
    }

    static String requireSecret(String secretKey) {
        if (secretKey == null || secretKey.isBlank()
                || secretKey.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalArgumentException(
                    "JWT signing secret must contain at least 32 bytes; configure USER_MANAGER_JWT_SECRET");
        }
        return secretKey;
    }

    public synchronized String registerUser(String email, String personalInfo) {
        email = normalizeEmail(email);
        if (personalInfo == null || personalInfo.length() > 2000
                || personalInfo.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Invalid personal information");
        }
        Map<String, Object> row = queryOne("SELECT * FROM users WHERE email = ? COLLATE NOCASE", email);
        if (row == null) {
            executeUpdate("INSERT INTO users (email, password, info) VALUES (?, ?, ?) "
                            + "ON CONFLICT(email COLLATE NOCASE) DO NOTHING",
                    email, "!reset-required!", personalInfo);
            row = queryOne("SELECT * FROM users WHERE email = ? COLLATE NOCASE", email);
        }
        if (((Number) row.get("email_verified")).intValue() == 0) {
            issueCode(row, "verification");
        }
        return "If the address can be registered, a verification code has been sent";
    }

    public Map<String, Object> authenticateUser(String email, String password, String clientIp) {
        String normalizedEmail = normalizeEmail(email);
        validateLoginPassword(password);
        if (clientIp == null || clientIp.isBlank() || clientIp.length() > 128) {
            throw new IllegalArgumentException("Invalid client address");
        }

        String accountKey = hashCode(normalizedEmail);
        AuthenticationAttempt attempt = reserveAuthentication(normalizedEmail, accountKey, clientIp);
        if (attempt == null) {
            return null;
        }
        boolean matches;
        String upgraded = null;
        try {
            passwordChecks.acquire();
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting to verify password", exception);
        }
        try {
            String storedHash = (String) attempt.user().get("password");
            matches = passwordVerifier.test(password, storedHash);
            if (matches && PasswordHasher.needsUpgrade(storedHash)) {
                upgraded = PasswordHasher.hash(password);
            }
        } finally {
            passwordChecks.release();
        }
        return finishAuthentication(attempt, accountKey, matches, upgraded);
    }

    private record AuthenticationAttempt(String reservation, Map<String, Object> user) { }

    private synchronized AuthenticationAttempt reserveAuthentication(
            String normalizedEmail, String accountKey, String clientIp) {
        long now = System.currentTimeMillis();
        try {
            connection.setAutoCommit(false);
            try (PreparedStatement cleanup = connection.prepareStatement(
                    "DELETE FROM authentication_limits WHERE expires_at <= ?")) {
                cleanup.setLong(1, now);
                cleanup.executeUpdate();
            }
            executeUpdate("DELETE FROM authentication_reservations WHERE expires_at <= ?", Long.toString(now));
            if (limitReached("ip", clientIp, IP_ATTEMPT_LIMIT)) {
                connection.commit();
                throw new RateLimitException();
            }
            incrementLimit("ip", clientIp, now);
            Map<String, Object> count = queryOne(
                    "SELECT COALESCE((SELECT attempts FROM authentication_limits "
                            + "WHERE scope = 'account' AND identity = ?), 0) + "
                            + "(SELECT COUNT(*) FROM authentication_reservations WHERE identity = ?) AS total",
                    accountKey, accountKey);
            if (((Number) count.get("total")).intValue() >= ACCOUNT_FAILURE_LIMIT) {
                connection.commit();
                throw new RateLimitException();
            }
            Map<String, Object> row = queryOne(
                    "SELECT * FROM users WHERE email = ? COLLATE NOCASE", normalizedEmail);
            if (row == null || ((Number) row.get("email_verified")).intValue() != 1) {
                incrementLimit("account", accountKey, now);
                connection.commit();
                return null;
            }
            String reservation = UUID.randomUUID().toString();
            executeUpdate("INSERT INTO authentication_reservations (id, identity, expires_at) VALUES (?, ?, ?)",
                    reservation, accountKey, Long.toString(now + LIMIT_WINDOW_MS));
            connection.commit();
            return new AuthenticationAttempt(reservation, row);
        } catch (SQLException exception) {
            rollback(exception);
            throw new IllegalStateException("Unable to process authentication", exception);
        } catch (RuntimeException exception) {
            rollback(exception);
            throw exception;
        } finally {
            try {
                connection.setAutoCommit(true);
            } catch (SQLException exception) {
                throw new IllegalStateException("Unable to restore database connection", exception);
            }
        }
    }

    private synchronized Map<String, Object> finishAuthentication(
            AuthenticationAttempt attempt, String accountKey, boolean matches, String upgraded) {
        try {
            connection.setAutoCommit(false);
            try (PreparedStatement delete = connection.prepareStatement(
                    "DELETE FROM authentication_reservations WHERE id = ? AND expires_at > ?")) {
                delete.setString(1, attempt.reservation());
                delete.setLong(2, System.currentTimeMillis());
                if (delete.executeUpdate() != 1) {
                    connection.commit();
                    return null;
                }
            }
            Map<String, Object> previous = attempt.user();
            Map<String, Object> current = queryOne("SELECT * FROM users WHERE id = ?",
                    previous.get("id").toString());
            if (!matches || current == null || ((Number) current.get("email_verified")).intValue() != 1
                    || !current.get("password").equals(previous.get("password"))
                    || !current.get("token_version").equals(previous.get("token_version"))) {
                incrementLimit("account", accountKey, System.currentTimeMillis());
                connection.commit();
                return null;
            }
            Map<String, Object> pending = queryOne(
                    "SELECT COUNT(*) AS total FROM authentication_reservations "
                            + "WHERE identity = ? AND expires_at > ?",
                    accountKey, Long.toString(System.currentTimeMillis()));
            // Avoid invalidating password snapshots held by other in-flight logins.
            if (upgraded != null && ((Number) pending.get("total")).intValue() == 0) {
                executeUpdate("UPDATE users SET password = ? WHERE id = ?",
                        upgraded, current.get("id").toString());
                current.put("password", upgraded);
            }
            executeUpdate("DELETE FROM authentication_limits WHERE scope = ? AND identity = ?",
                    "account", accountKey);
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("token", createToken(current));
            result.put("user", current);
            connection.commit();
            return result;
        } catch (SQLException exception) {
            rollback(exception);
            throw new IllegalStateException("Unable to process authentication", exception);
        } catch (RuntimeException exception) {
            rollback(exception);
            throw exception;
        } finally {
            try {
                connection.setAutoCommit(true);
            } catch (SQLException exception) {
                throw new IllegalStateException("Unable to restore database connection", exception);
            }
        }
    }

    public Map<String, Object> authenticateUser(String email, String password) {
        return authenticateUser(email, password, "direct");
    }

    private boolean limitReached(String scope, String identity, int max) {
        Map<String, Object> row = queryOne(
                "SELECT attempts FROM authentication_limits WHERE scope = ? AND identity = ?", scope, identity);
        return row != null && ((Number) row.get("attempts")).intValue() >= max;
    }

    private void incrementLimit(String scope, String identity, long now) {
        executeUpdate("INSERT INTO authentication_limits (scope, identity, attempts, expires_at) "
                + "VALUES (?, ?, 1, ?) ON CONFLICT(scope, identity) "
                + "DO UPDATE SET attempts = attempts + 1", scope, identity, Long.toString(now + LIMIT_WINDOW_MS));
    }

    private void rollback(Exception cause) {
        try {
            connection.rollback();
        } catch (SQLException exception) {
            cause.addSuppressed(exception);
        }
    }

    public synchronized String requestPasswordReset(String email) {
        Map<String, Object> user = queryOne("SELECT * FROM users WHERE email = ? COLLATE NOCASE",
                normalizeEmail(email));
        if (user != null) {
            issueCode(user, "recovery");
        }
        return "If the account exists, a recovery code has been sent";
    }

    public synchronized String verifyEmail(String email, String password, String code) {
        consumeCode(email, password, code, "verification");
        return "Email verified";
    }

    public synchronized String resetPassword(String email, String newPassword, String resetToken) {
        consumeCode(email, newPassword, resetToken, "recovery");
        return "Password reset";
    }

    public synchronized Map<String, Object> getUserDataForToken(String userId, String token) {
        if (userId == null || !userId.matches("[1-9][0-9]{0,18}") || token == null || token.length() > 4096) {
            throw new IllegalArgumentException("Invalid user ID or token");
        }
        DecodedJWT claims = JWT.require(Algorithm.HMAC256(secretKey))
                .withIssuer("user-manager").withAudience("user-api").build().verify(token);
        if (claims.getExpiresAt() == null) {
            throw new SecurityException("Token expiration is required");
        }
        if (!userId.equals(claims.getSubject())) {
            throw new SecurityException("Users may only access their own data");
        }
        Map<String, Object> user = queryOne("SELECT * FROM users WHERE id = ?", userId);
        Integer tokenVersion = claims.getClaim("version").asInt();
        if (user != null && (((Number) user.get("email_verified")).intValue() != 1
                || tokenVersion == null
                || !tokenVersion.equals(((Number) user.get("token_version")).intValue()))) {
            throw new SecurityException("Token is no longer valid");
        }
        return user;
    }

    @Override
    public synchronized void close() throws SQLException {
        connection.close();
    }

    private String createToken(Map<String, Object> user) {
        Algorithm algorithm = Algorithm.HMAC256(secretKey);
        return JWT.create()
                .withIssuer("user-manager")
                .withAudience("user-api")
                .withSubject(user.get("id").toString())
                .withClaim("email", user.get("email").toString())
                .withClaim("version", ((Number) user.get("token_version")).intValue())
                .withExpiresAt(new Date(System.currentTimeMillis() + 15 * 60 * 1000L))
                .sign(algorithm);
    }

    private void issueCode(Map<String, Object> user, String purpose) {
        byte[] random = new byte[32];
        RANDOM.nextBytes(random);
        String code = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        String id = user.get("id").toString();
        String codeHash = hashCode(code);
        long now = System.currentTimeMillis();
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO email_codes (user_id, purpose, code_hash, expires_at) VALUES (?, ?, ?, ?) "
                        + "ON CONFLICT(user_id, purpose) DO UPDATE SET code_hash = excluded.code_hash, "
                        + "expires_at = excluded.expires_at WHERE email_codes.expires_at <= ?")) {
            statement.setString(1, id);
            statement.setString(2, purpose);
            statement.setString(3, codeHash);
            statement.setLong(4, now + 15 * 60 * 1000L);
            statement.setLong(5, now + 14 * 60 * 1000L);
            if (statement.executeUpdate() == 0) {
                return;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to create email code", exception);
        }
        try {
            emailSender.sendCode(user.get("email").toString(), purpose, code);
        } catch (RuntimeException exception) {
            try {
                executeUpdate("DELETE FROM email_codes WHERE user_id = ? AND purpose = ? AND code_hash = ?",
                        id, purpose, codeHash);
            } catch (IllegalStateException cleanupException) {
                exception.addSuppressed(cleanupException);
            }
            throw exception;
        }
    }

    private void consumeCode(String email, String password, String code, String purpose) {
        validateNewPassword(password);
        if (code == null || !code.matches("[A-Za-z0-9_-]{43}")) {
            throw new SecurityException("Invalid or expired code");
        }
        Map<String, Object> user = queryOne("SELECT * FROM users WHERE email = ? COLLATE NOCASE",
                normalizeEmail(email));
        if (user == null) {
            throw new SecurityException("Invalid or expired code");
        }
        String codeHash = hashCode(code);
        Map<String, Object> validCode = queryOne(
                "SELECT user_id FROM email_codes WHERE user_id = ? AND purpose = ? "
                        + "AND code_hash = ? AND expires_at > ?",
                user.get("id").toString(), purpose, codeHash, Long.toString(System.currentTimeMillis()));
        if (validCode == null) {
            throw new SecurityException("Invalid or expired code");
        }
        String hash = PasswordHasher.hash(password);
        try {
            connection.setAutoCommit(false);
            try (PreparedStatement statement = connection.prepareStatement(
                    "DELETE FROM email_codes WHERE user_id = ? AND purpose = ? "
                            + "AND code_hash = ? AND expires_at > ?")) {
                statement.setString(1, user.get("id").toString());
                statement.setString(2, purpose);
                statement.setString(3, codeHash);
                statement.setLong(4, System.currentTimeMillis());
                if (statement.executeUpdate() != 1) {
                    connection.rollback();
                    throw new SecurityException("Invalid or expired code");
                }
            }
            executeUpdate("UPDATE users SET password = ?, email_verified = 1, "
                    + "token_version = token_version + 1 WHERE id = ?", hash, user.get("id").toString());
            executeUpdate("DELETE FROM email_codes WHERE user_id = ?", user.get("id").toString());
            connection.commit();
        } catch (SQLException exception) {
            try {
                connection.rollback();
            } catch (SQLException rollbackException) {
                exception.addSuppressed(rollbackException);
            }
            throw new IllegalStateException("Unable to consume email code", exception);
        } catch (RuntimeException exception) {
            try {
                connection.rollback();
            } catch (SQLException rollbackException) {
                exception.addSuppressed(rollbackException);
            }
            throw exception;
        } finally {
            try {
                connection.setAutoCommit(true);
            } catch (SQLException exception) {
                throw new IllegalStateException("Unable to restore database connection", exception);
            }
        }
    }

    private static String hashCode(String code) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(code.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    static String normalizeEmail(String email) {
        if (email == null || email.length() > 254 || !email.matches(
                "[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+")) {
            throw new IllegalArgumentException("Invalid email address");
        }
        return email.toLowerCase(Locale.ROOT);
    }

    private static void validateLoginPassword(String password) {
        if (password == null || password.isBlank() || password.length() > 128) {
            throw new IllegalArgumentException("Invalid password");
        }
    }

    private static void validateNewPassword(String password) {
        validateLoginPassword(password);
        if (password.length() < 12) {
            throw new IllegalArgumentException("Password must contain at least 12 characters");
        }
    }

    private void executeUpdate(String query, String... values) {
        try (PreparedStatement statement = connection.prepareStatement(query)) {
            bindValues(statement, values);
            statement.executeUpdate();
        } catch (SQLException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private Map<String, Object> queryOne(String query, String... values) {
        try (PreparedStatement statement = connection.prepareStatement(query)) {
            bindValues(statement, values);
            try (ResultSet results = statement.executeQuery()) {
                if (!results.next()) {
                    return null;
                }
                ResultSetMetaData metadata = results.getMetaData();
                Map<String, Object> row = new LinkedHashMap<>();
                for (int index = 1; index <= metadata.getColumnCount(); index++) {
                    row.put(metadata.getColumnLabel(index), results.getObject(index));
                }
                return row;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static void bindValues(PreparedStatement statement, String... values) throws SQLException {
        for (int index = 0; index < values.length; index++) {
            statement.setString(index + 1, values[index]);
        }
    }

}
