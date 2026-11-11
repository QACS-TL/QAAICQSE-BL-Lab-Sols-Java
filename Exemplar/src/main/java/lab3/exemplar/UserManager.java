package lab3.exemplar;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Typical AI-generated user manager for Lab 3 review.
 * The vulnerabilities marked below are intentional.
 */
public class UserManager implements AutoCloseable {
    private final Connection connection;

    // VULNERABLE: Hardcoded secret
    private final String secretKey = "secret123";

    public UserManager() {
        this(openConnection());
    }

    UserManager(Connection connection) {
        this.connection = connection;
    }

    private static Connection openConnection() {
        try {
            return DriverManager.getConnection("jdbc:sqlite:users.db");
        } catch (SQLException exception) {
            throw new IllegalStateException(exception);
        }
    }

    public String registerUser(String email, String password, String personalInfo) {
        String hashedPassword = hashPassword(password); // VULNERABLE: Weak hashing
        executeUpdate(
                "INSERT INTO users (email, password, info) VALUES (?, ?, ?)",
                email,
                hashedPassword,
                personalInfo);
        return "User registered";
    }

    public Map<String, Object> authenticateUser(String email, String password) {
        String hashedPassword = hashPassword(password);
        Map<String, Object> row = queryOne(
                "SELECT * FROM users WHERE email = ? AND password = ?",
                email,
                hashedPassword);
        if (row == null) {
            return null;
        }

        String token = createToken(email);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("token", token);
        result.put("user", row);
        return result;
    }

    public String resetPassword(String email, String newPassword, String resetToken) {
        String tokenEmail = verifyToken(resetToken);
        if (!email.equals(tokenEmail)) {
            throw new SecurityException("Reset token does not match the requested account");
        }
        String hashedPassword = hashPassword(newPassword);
        executeUpdate("UPDATE users SET password = ? WHERE email = ?", hashedPassword, email);
        return "Password reset";
    }

    public Map<String, Object> getUserData(String userId, String requestingUserId) {
        if (!userId.equals(requestingUserId)) {
            throw new SecurityException("Users may only access their own data");
        }
        return queryOne("SELECT * FROM users WHERE id = ?", userId);
    }

    public Map<String, Object> getUserDataForToken(String userId, String token) {
        String email = verifyToken(token);
        Map<String, Object> user = queryOne("SELECT * FROM users WHERE id = ?", userId);
        if (user != null && !email.equals(user.get("email"))) {
            throw new SecurityException("Users may only access their own data");
        }
        return user;
    }

    @Override
    public void close() throws SQLException {
        connection.close();
    }

    private String createToken(String email) {
        Algorithm algorithm = Algorithm.HMAC256(secretKey);
        return JWT.create()
                .withClaim("email", email)
                .withExpiresAt(new Date(System.currentTimeMillis() + 15 * 60 * 1000L))
                .sign(algorithm);
    }

    private String verifyToken(String token) {
        return JWT.require(Algorithm.HMAC256(secretKey))
                .build()
                .verify(token)
                .getClaim("email")
                .asString();
    }

    // VULNERABLE: Weak hashing
    private static String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte value : hash) {
                hex.append(String.format("%02x", value));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
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
