package lab3.exemplar;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

@Configuration
class UserManagerConfiguration {
    record JwtSecret(String value) {
    }

    @Bean
    JwtSecret jwtSecret(@Value("${app.jwt.secret:}") String secret) {
        return new JwtSecret(UserManager.requireSecret(secret));
    }

    @Bean(destroyMethod = "close")
    @DependsOn({"emailSender", "jwtSecret"})
    Connection userDatabaseConnection(
            @Value("${app.database.url:jdbc:sqlite:users.db}") String databaseUrl) throws SQLException {
        Connection connection = DriverManager.getConnection(databaseUrl);
        try {
            try (Statement statement = connection.createStatement()) {
                statement.execute("PRAGMA secure_delete = ON");
                statement.execute("PRAGMA busy_timeout = 10000");
            }
            connection.setAutoCommit(false);
            try (Statement statement = connection.createStatement()) {
                statement.executeUpdate(
                        "CREATE TABLE IF NOT EXISTS users "
                                + "(id INTEGER PRIMARY KEY, email TEXT NOT NULL, "
                                + "password TEXT NOT NULL, info TEXT)");
                boolean verified = false;
                boolean version = false;
                try (ResultSet columns = statement.executeQuery("PRAGMA table_info(users)")) {
                    while (columns.next()) {
                        verified |= "email_verified".equals(columns.getString("name"));
                        version |= "token_version".equals(columns.getString("name"));
                    }
                }
                if (!verified) {
                    statement.executeUpdate("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0");
                }
                if (!version) {
                    statement.executeUpdate("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0");
                }
                List<String[]> users = new ArrayList<>();
                try (ResultSet rows = statement.executeQuery("SELECT id, email FROM users")) {
                    while (rows.next()) {
                        String email = rows.getString("email");
                        if (email == null || email.isBlank()) {
                            throw new SQLException("A user has a missing email address");
                        }
                        try {
                            users.add(new String[] {rows.getString("id"), UserManager.normalizeEmail(email)});
                        } catch (IllegalArgumentException exception) {
                            throw new SQLException("A user has an invalid email address", exception);
                        }
                    }
                }
                try (PreparedStatement update = connection.prepareStatement("UPDATE users SET email = ? WHERE id = ?")) {
                    for (String[] user : users) {
                        update.setString(1, user[1]);
                        update.setString(2, user[0]);
                        update.executeUpdate();
                    }
                }
                statement.executeUpdate("CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique "
                        + "ON users(email COLLATE NOCASE)");
                statement.executeUpdate("CREATE TABLE IF NOT EXISTS email_codes "
                        + "(user_id INTEGER NOT NULL, purpose TEXT NOT NULL, code_hash TEXT NOT NULL, "
                        + "expires_at INTEGER NOT NULL, PRIMARY KEY(user_id, purpose))");
                statement.executeUpdate("CREATE TABLE IF NOT EXISTS authentication_limits "
                        + "(scope TEXT NOT NULL, identity TEXT NOT NULL, attempts INTEGER NOT NULL, "
                        + "expires_at INTEGER NOT NULL, PRIMARY KEY(scope, identity))");
                statement.executeUpdate("CREATE TABLE IF NOT EXISTS authentication_reservations "
                        + "(id TEXT PRIMARY KEY, identity TEXT NOT NULL, expires_at INTEGER NOT NULL)");
                statement.executeUpdate("CREATE INDEX IF NOT EXISTS authentication_reservations_identity "
                        + "ON authentication_reservations(identity)");
                statement.executeUpdate("UPDATE users SET password = '!reset-required!' "
                        + "WHERE length(password) = 32 AND password NOT GLOB '*[^0-9a-f]*'");
            }
            connection.commit();
            connection.setAutoCommit(true);
        } catch (SQLException exception) {
            try {
                connection.rollback();
            } catch (SQLException rollbackException) {
                exception.addSuppressed(rollbackException);
            }
            try {
                connection.close();
            } catch (SQLException closeException) {
                exception.addSuppressed(closeException);
            }
            throw new SQLException("Database migration failed; check the cause and resolve duplicate "
                    + "or invalid email addresses before startup", exception);
        }
        return connection;
    }

    @Bean
    EmailSender emailSender(JavaMailSender mailSender, @Value("${app.mail.from}") String from,
            @Value("${spring.mail.host:}") String host) {
        if (from.isBlank() || host.isBlank()) {
            throw new IllegalArgumentException("Configure app.mail.from and spring.mail.host");
        }
        return (email, purpose, code) -> {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(from);
            message.setTo(email);
            message.setSubject("User account " + purpose + " code");
            message.setText("Your " + purpose + " code is: " + code + "\nIt expires in 15 minutes.");
            mailSender.send(message);
        };
    }

    @Bean(destroyMethod = "")
    UserManager userManager(Connection userDatabaseConnection,
            JwtSecret secretKey, EmailSender emailSender) {
        return new UserManager(userDatabaseConnection, secretKey.value(), emailSender);
    }
}
