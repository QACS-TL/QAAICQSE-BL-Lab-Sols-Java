package lab3.exemplar;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

@Configuration
class UserManagerConfiguration {
    @Bean(destroyMethod = "close")
    Connection userDatabaseConnection(
            @Value("${app.database.url:jdbc:sqlite:users.db}") String databaseUrl) throws SQLException {
        Connection connection = DriverManager.getConnection(databaseUrl);
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(
                    "CREATE TABLE IF NOT EXISTS users "
                            + "(id INTEGER PRIMARY KEY, email TEXT NOT NULL, "
                            + "password TEXT NOT NULL, info TEXT)");
        } catch (SQLException exception) {
            connection.close();
            throw exception;
        }
        return connection;
    }

    @Bean(destroyMethod = "")
    UserManager userManager(Connection userDatabaseConnection) {
        return new UserManager(userDatabaseConnection);
    }
}
