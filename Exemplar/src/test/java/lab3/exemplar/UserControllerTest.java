package lab3.exemplar;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.sql.Connection;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

@SpringBootTest(properties = {
        "app.database.url=jdbc:sqlite::memory:",
        "app.jwt.secret=api-test-only-signing-key-not-for-production",
        "app.mail.from=test@example.com",
        "spring.mail.host=localhost"
})
@AutoConfigureMockMvc
@Import(UserControllerTest.FakeMailConfiguration.class)
class UserControllerTest {
    @TestConfiguration
    static class FakeMailConfiguration {
        @Bean
        @Primary
        CapturingSender capturingSender() {
            return new CapturingSender();
        }
    }

    static class CapturingSender implements EmailSender {
        final List<String> codes = new ArrayList<>();

        @Override
        public void sendCode(String email, String purpose, String code) {
            codes.add(code);
        }
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper mapper;
    @Autowired private Connection connection;
    @Autowired private CapturingSender sender;

    @BeforeEach
    void clearUsers() throws Exception {
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate("DELETE FROM email_codes");
            statement.executeUpdate("DELETE FROM authentication_limits");
            statement.executeUpdate("DELETE FROM users");
        }
        sender.codes.clear();
    }

    @Test
    void registrationVerificationAndAuthenticatedProfile() throws Exception {
        request("/api/users/register", Map.of("email", "alice@example.com", "personalInfo", "Alice"))
                .andExpect(status().isAccepted());
        request("/api/users/authenticate", Map.of("email", "alice@example.com", "password", "password-long"))
                .andExpect(status().isUnauthorized());
        request("/api/users/verify", Map.of("email", "alice@example.com", "password", "password-long",
                "code", sender.codes.get(0))).andExpect(status().isOk());
        String body = request("/api/users/authenticate",
                Map.of("email", "alice@example.com", "password", "password-long"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        JsonNode authentication = mapper.readTree(body);
        assertFalse(authentication.get("user").has("password"));
        assertFalse(authentication.get("user").has("token_version"));
        mockMvc.perform(get("/api/users/1")
                .header("Authorization", "Bearer " + authentication.get("token").asText()))
                .andExpect(status().isOk());
    }

    @Test
    void invalidEmailAndUnauthenticatedProfileAreRejected() throws Exception {
        request("/api/users/register", Map.of("email", "invalid", "personalInfo", "Alice"))
                .andExpect(status().isBadRequest());
        mockMvc.perform(get("/api/users/1")).andExpect(status().isUnauthorized());
    }

    @Test
    void authenticationReturns429AfterFiveFailures() throws Exception {
        for (int i = 0; i < 5; i++) {
            request("/api/users/authenticate", Map.of("email", "unknown@example.com", "password", "bad"))
                    .andExpect(status().isUnauthorized());
        }
        request("/api/users/authenticate", Map.of("email", "unknown@example.com", "password", "bad"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "900"));
    }

    @Test
    void verificationRejectsWeakPasswordWithoutConsumingCode() throws Exception {
        request("/api/users/register", Map.of("email", "alice@example.com", "personalInfo", "Alice"))
                .andExpect(status().isAccepted());
        request("/api/users/verify", Map.of("email", "alice@example.com", "password", "short",
                "code", sender.codes.get(0))).andExpect(status().isBadRequest());
        request("/api/users/verify", Map.of("email", "alice@example.com", "password", "password-long",
                "code", sender.codes.get(0))).andExpect(status().isOk());
    }

    @Test
    void recoveryRequiresEmailCode() throws Exception {
        request("/api/users/register", Map.of("email", "alice@example.com", "personalInfo", "Alice"))
                .andExpect(status().isAccepted());
        request("/api/users/verify", Map.of("email", "alice@example.com", "password", "old-password",
                "code", sender.codes.get(0))).andExpect(status().isOk());
        request("/api/users/password-reset/request", Map.of("email", "alice@example.com"))
                .andExpect(status().isAccepted());
        request("/api/users/password-reset", Map.of("email", "alice@example.com",
                "newPassword", "new-password", "resetToken", "invalid")).andExpect(status().isForbidden());
        request("/api/users/password-reset", Map.of("email", "alice@example.com",
                "newPassword", "new-password", "resetToken", sender.codes.get(1))).andExpect(status().isOk());
        request("/api/users/authenticate", Map.of("email", "alice@example.com", "password", "old-password"))
                .andExpect(status().isUnauthorized());
        request("/api/users/authenticate", Map.of("email", "alice@example.com", "password", "new-password"))
                .andExpect(status().isOk());
    }

    private org.springframework.test.web.servlet.ResultActions request(String path, Map<String, String> body)
            throws Exception {
        return mockMvc.perform(post(path).contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(body)));
    }
}
