package lab3.exemplar;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.sql.Connection;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "app.database.url=jdbc:sqlite::memory:")
@AutoConfigureMockMvc
class UserControllerTest {
    private static final String EMAIL = "alice@example.com";
    private static final String PASSWORD = "correct-horse";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private Connection connection;

    @BeforeEach
    void clearUsers() throws Exception {
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate("DELETE FROM users");
        }
    }

    @Test
    void registrationAndAuthenticationReturnTokenWithoutPasswordHash() throws Exception {
        register(EMAIL, PASSWORD, "Alice Smith")
                .andExpect(status().isCreated())
                .andExpect(content().string("User registered"));

        String response = authenticate(EMAIL, PASSWORD)
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        JsonNode authentication = objectMapper.readTree(response);

        assertFalse(authentication.get("token").asText().isBlank());
        assertFalse(authentication.get("user").has("password"));
        org.junit.jupiter.api.Assertions.assertEquals(EMAIL,
                authentication.get("user").get("email").asText());
    }

    @Test
    void authenticationRejectsInvalidCredentials() throws Exception {
        authenticate(EMAIL, PASSWORD).andExpect(status().isUnauthorized());
    }

    @Test
    void passwordResetRequiresValidTokenAndChangesCredentials() throws Exception {
        register(EMAIL, PASSWORD, "Alice Smith");
        String authentication = authenticate(EMAIL, PASSWORD)
                .andReturn()
                .getResponse()
                .getContentAsString();
        String token = objectMapper.readTree(authentication).get("token").asText();

        mockMvc.perform(post("/api/users/password-reset")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"alice@example.com","newPassword":"new-password","resetToken":"%s"}
                                """.formatted(token)))
                .andExpect(status().isOk())
                .andExpect(content().string("Password reset"));

        authenticate(EMAIL, PASSWORD).andExpect(status().isUnauthorized());
        authenticate(EMAIL, "new-password").andExpect(status().isOk());
    }

    @Test
    void userLookupRequiresTokenAndReturnsOnlyOwnUserData() throws Exception {
        register(EMAIL, PASSWORD, "Alice Smith");
        String authentication = authenticate(EMAIL, PASSWORD)
                .andReturn()
                .getResponse()
                .getContentAsString();
        String token = objectMapper.readTree(authentication).get("token").asText();

        mockMvc.perform(get("/api/users/1"))
                .andExpect(status().isUnauthorized());

        String userResponse = mockMvc.perform(get("/api/users/1")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        JsonNode user = objectMapper.readTree(userResponse);

        org.junit.jupiter.api.Assertions.assertEquals(EMAIL, user.get("email").asText());
        org.junit.jupiter.api.Assertions.assertEquals("Alice Smith", user.get("info").asText());
        assertFalse(user.has("password"));
    }

    @Test
    void userLookupDoesNotExposeAnotherAccount() throws Exception {
        register(EMAIL, PASSWORD, "Alice Smith");
        String authentication = authenticate(EMAIL, PASSWORD)
                .andReturn()
                .getResponse()
                .getContentAsString();
        String token = objectMapper.readTree(authentication).get("token").asText();
        register("bob@example.com", PASSWORD, "Bob Smith");

        mockMvc.perform(get("/api/users/2")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    void registrationValidatesEmail() throws Exception {
        mockMvc.perform(post("/api/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"not-an-email","password":"password","personalInfo":"Alice"}
                                """))
                .andExpect(status().isBadRequest());
    }

    private org.springframework.test.web.servlet.ResultActions register(
            String email, String password, String personalInfo) throws Exception {
        return mockMvc.perform(post("/api/users/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                        new UserController.RegisterRequest(email, password, personalInfo))));
    }

    private org.springframework.test.web.servlet.ResultActions authenticate(
            String email, String password) throws Exception {
        return mockMvc.perform(post("/api/users/authenticate")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                        new UserController.AuthenticationRequest(email, password))));
    }
}
