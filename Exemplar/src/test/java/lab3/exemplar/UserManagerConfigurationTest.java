package lab3.exemplar;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class UserManagerConfigurationTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(UserManagerConfiguration.class)
            .withBean(JavaMailSender.class, JavaMailSenderImpl::new)
            .withPropertyValues("app.database.url=jdbc:sqlite::memory:",
                    "app.mail.from=test@example.com", "spring.mail.host=localhost");

    @Test
    void missingSigningSecretPreventsStartup() {
        runner.withPropertyValues("app.jwt.secret=")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void weakSigningSecretPreventsStartup() {
        runner.withPropertyValues("app.jwt.secret=secret123")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalArgumentException.class);
                });
    }

    @Test
    void configuredSigningSecretAllowsStartup() {
        runner.withPropertyValues("app.jwt.secret=configuration-test-only-signing-key")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(UserManager.class);
                });
    }

    @Test
    void missingSmtpSettingsPreventStartup() {
        runner.withPropertyValues("app.jwt.secret=configuration-test-only-signing-key",
                        "spring.mail.host=")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalArgumentException.class);
                });
    }

    @Test
    void missingSmtpSettingsDoNotMigrateDatabase(@TempDir Path tempDir) throws SQLException {
        String url = "jdbc:sqlite:" + tempDir.resolve("unconfigured.db");
        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement()) {
            statement.executeUpdate("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password TEXT, info TEXT)");
            statement.executeUpdate("INSERT INTO users VALUES (1, 'a@example.com', "
                    + "'5f4dcc3b5aa765d61d8327deb882cf99', 'Alice')");
        }
        runner.withPropertyValues("app.database.url=" + url, "spring.mail.host=",
                        "app.jwt.secret=configuration-test-only-signing-key")
                .run(context -> assertThat(context).hasFailed());
        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement();
                ResultSet row = statement.executeQuery("SELECT password FROM users")) {
            row.next();
            assertEquals("5f4dcc3b5aa765d61d8327deb882cf99", row.getString("password"));
        }
    }

    @Test
    void migrationDisablesLegacyHash(@TempDir Path tempDir) throws SQLException {
        String url = "jdbc:sqlite:" + tempDir.resolve("legacy.db");
        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement()) {
            statement.executeUpdate("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password TEXT, info TEXT)");
            statement.executeUpdate("INSERT INTO users VALUES (1, 'a@example.com', "
                    + "'5f4dcc3b5aa765d61d8327deb882cf99', 'Alice')");
        }
        try (Connection migrated = new UserManagerConfiguration().userDatabaseConnection(url);
                Statement statement = migrated.createStatement();
                ResultSet row = statement.executeQuery("SELECT password, email_verified FROM users")) {
            row.next();
            assertEquals("!reset-required!", row.getString("password"));
            assertEquals(0, row.getInt("email_verified"));
        }
    }

    @Test
    void duplicateEmailsAbortMigrationWithoutInvalidatingHashes(@TempDir Path tempDir) throws SQLException {
        String url = "jdbc:sqlite:" + tempDir.resolve("duplicates.db");
        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement()) {
            statement.executeUpdate("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password TEXT, info TEXT)");
            statement.executeUpdate("INSERT INTO users VALUES "
                    + "(1, 'a@example.com', '5f4dcc3b5aa765d61d8327deb882cf99', 'Alice'), "
                    + "(2, 'A@example.com', 'another', 'Other')");
        }
        assertThrows(SQLException.class, () -> new UserManagerConfiguration().userDatabaseConnection(url));
        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement();
                ResultSet row = statement.executeQuery("SELECT password FROM users WHERE id = 1")) {
            row.next();
            assertEquals("5f4dcc3b5aa765d61d8327deb882cf99", row.getString("password"));
        }
    }
}
