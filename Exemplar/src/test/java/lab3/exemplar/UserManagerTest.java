package lab3.exemplar;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class UserManagerTest {
    private static final String EMAIL = "alice@example.com";
    private static final String PASSWORD = "correct-horse";

    private Connection connection;
    private UserManager userManager;
    private boolean connectionClosed;

    @BeforeEach
    void setUp() throws SQLException {
        connection = DriverManager.getConnection("jdbc:sqlite::memory:");
        userManager = new UserManager(connection);
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(
                    "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password TEXT, info TEXT)");
        }
    }

    @AfterEach
    void tearDown() throws SQLException {
        if (!connectionClosed) {
            userManager.close();
        }
    }

    @Test
    void registerUserStoresUserAndReturnsConfirmation() {
        String result = userManager.registerUser(EMAIL, PASSWORD, "Alice Smith");

        assertEquals("User registered", result);
        Map<String, Object> response = userManager.authenticateUser(EMAIL, PASSWORD);
        assertEquals(EMAIL, ((Map<?, ?>) response.get("user")).get("email"));
    }

    @Test
    void authenticateUserReturnsNullWhenNoMatchingUserExists() {
        assertNull(userManager.authenticateUser(EMAIL, PASSWORD));
    }

    @Test
    void authenticateUserReturnsUserAndSignedTokenWhenMatchExists() {
        userManager.registerUser(EMAIL, PASSWORD, "Alice Smith");

        Map<String, Object> response = userManager.authenticateUser(EMAIL, PASSWORD);

        assertEquals(EMAIL, ((Map<?, ?>) response.get("user")).get("email"));
        DecodedJWT token = JWT.require(Algorithm.HMAC256("secret123"))
                .build()
                .verify((String) response.get("token"));
        assertEquals(EMAIL, token.getClaim("email").asString());
    }

    @Test
    void resetPasswordUpdatesPasswordAndReturnsConfirmation() {
        userManager.registerUser(EMAIL, PASSWORD, "Alice Smith");
        String resetToken = (String) userManager.authenticateUser(EMAIL, PASSWORD).get("token");

        String result = userManager.resetPassword(EMAIL, "new-password", resetToken);

        assertEquals("Password reset", result);
        assertNull(userManager.authenticateUser(EMAIL, PASSWORD));
        assertEquals(EMAIL, ((Map<?, ?>) userManager.authenticateUser(EMAIL, "new-password")
                .get("user")).get("email"));
    }

    @Test
    void getUserDataReturnsRowForRequestedId() {
        userManager.registerUser(EMAIL, PASSWORD, "Alice Smith");

        Map<String, Object> user = userManager.getUserData("1", "1");

        assertEquals(EMAIL, user.get("email"));
        assertEquals("Alice Smith", user.get("info"));
    }

    @Test
    void databaseErrorsAreReportedAsIllegalStateException() throws SQLException {
        connection.close();
        connectionClosed = true;

        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> userManager.registerUser(EMAIL, PASSWORD, "Alice Smith"));

        assertEquals(SQLException.class, exception.getCause().getClass());
    }

    @Test
    void closeClosesDatabaseConnection() throws SQLException {
        userManager.close();
        connectionClosed = true;

        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> userManager.registerUser(EMAIL, PASSWORD, "Alice Smith"));
        assertEquals(SQLException.class, exception.getCause().getClass());
    }
}
