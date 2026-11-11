package lab3.exemplar;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "app.database.url=jdbc:sqlite::memory:",
        "app.jwt.secret=api-test-only-signing-key-not-for-production",
        "app.mail.from=test@example.com",
        "spring.mail.host=localhost"
})
@AutoConfigureMockMvc
@Import(UserControllerTest.FakeMailConfiguration.class)
class UserApiSecurityTest {
    private static final String SECRET = "api-test-only-signing-key-not-for-production";
    private static final String ALICE = "alice@example.com";
    private static final String BOB = "bob@example.com";
    private static final String PASSWORD = "correct-password";
    private static final String ATTACKER_PASSWORD = "attacker-password";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper mapper;
    @Autowired private Connection connection;
    @Autowired private UserControllerTest.CapturingSender sender;

    @BeforeEach
    void resetDatabase() throws Exception {
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate("DELETE FROM email_codes");
            statement.executeUpdate("DELETE FROM authentication_reservations");
            statement.executeUpdate("DELETE FROM authentication_limits");
            statement.executeUpdate("DELETE FROM users");
        }
        sender.codes.clear();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "' OR '1'='1",
            "'); DROP TABLE users; --",
            "' UNION SELECT id,email,password,info FROM users --"
    })
    void sqlPayloadsAreStoredAsDataAndCannotAlterOtherAccounts(String payload) throws Exception {
        createVerifiedUser(ALICE, "Alice");
        postJson("/api/users/register", Map.of("email", BOB, "personalInfo", payload))
                .andExpect(status().isAccepted());
        verify(BOB, PASSWORD, sender.codes.get(1)).andExpect(status().isOk());

        JsonNode bob = login(BOB, PASSWORD);
        assertEquals(payload, bob.path("user").path("info").asText());
        assertEquals(ALICE, login(ALICE, PASSWORD).path("user").path("email").asText());
        try (Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery("SELECT COUNT(*) FROM users")) {
            assertTrue(result.next());
            assertEquals(2, result.getInt(1));
        }
    }

    @Test
    void injectionInCredentialsAndUserIdDoesNotAuthenticateOrExposeRows() throws Exception {
        createVerifiedUser(ALICE, "Alice");
        String token = login(ALICE, PASSWORD).path("token").asText();

        postJson("/api/users/authenticate",
                Map.of("email", "' OR 1=1 --", "password", "anything"))
                .andExpect(status().isBadRequest());
        postJson("/api/users/authenticate",
                Map.of("email", "'or'1'='1@example.com", "password", PASSWORD))
                .andExpect(status().isUnauthorized());
        postJson("/api/users/authenticate",
                Map.of("email", ALICE, "password", "' OR '1'='1"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/users/{id}", "1 OR 1=1").header("Authorization", "Bearer " + token))
                .andExpect(status().isBadRequest());

        assertEquals(ALICE, login(ALICE, PASSWORD).path("user").path("email").asText());
    }

    @Test
    void anotherUsersTokenAndRecoveryCodeCannotAccessOrChangeVictim() throws Exception {
        createVerifiedUser(ALICE, "Alice");
        createVerifiedUser(BOB, "Bob");
        String aliceToken = login(ALICE, PASSWORD).path("token").asText();
        String bobToken = login(BOB, PASSWORD).path("token").asText();

        mockMvc.perform(get("/api/users/1")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/users/1").header("Authorization", "Bearer " + bobToken))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/users/1").header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isOk());

        postJson("/api/users/password-reset/request", Map.of("email", BOB))
                .andExpect(status().isAccepted());
        String bobCode = sender.codes.get(2);
        postJson("/api/users/password-reset", Map.of(
                "email", ALICE, "newPassword", ATTACKER_PASSWORD, "resetToken", bobCode))
                .andExpect(status().isForbidden());
        postJson("/api/users/password-reset", Map.of(
                "email", ALICE, "newPassword", ATTACKER_PASSWORD, "resetToken", bobToken))
                .andExpect(status().isBadRequest());
        assertEquals(ALICE, login(ALICE, PASSWORD).path("user").path("email").asText());
    }

    @Test
    void distributedPasswordGuessingLocksTheAccountAtTheSpecifiedBoundary() throws Exception {
        createVerifiedUser(ALICE, "Alice");
        for (int attempt = 0; attempt < 5; attempt++) {
            postFrom("/api/users/authenticate", Map.of("email", ALICE, "password", "guess-" + attempt),
                    "192.0.2." + (attempt + 1)).andExpect(status().isUnauthorized());
        }
        postFrom("/api/users/authenticate", Map.of("email", ALICE, "password", PASSWORD), "192.0.2.10")
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "900"));
    }

    @Test
    void passwordSprayingAcrossAccountsHitsIpLimitAndIgnoresSpoofedForwardedFor() throws Exception {
        for (int attempt = 0; attempt < 30; attempt++) {
            postFrom("/api/users/authenticate",
                    Map.of("email", "unknown" + attempt + "@example.com", "password", "wrong"),
                    "192.0.2.42").andExpect(status().isUnauthorized());
        }
        mockMvc.perform(post("/api/users/authenticate")
                        .with(request -> {
                            request.setRemoteAddr("192.0.2.42");
                            return request;
                        })
                        .header("X-Forwarded-For", "203.0.113.200")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of("email", "new@example.com", "password", "wrong"))))
                .andExpect(status().isTooManyRequests());
        postFrom("/api/users/authenticate", Map.of("email", "new@example.com", "password", "wrong"),
                "192.0.2.43").andExpect(status().isUnauthorized());
    }

    @Test
    void manipulatedJwtPayloadUnsignedTokenAndMalformedTokenAreRejected() throws Exception {
        createVerifiedUser(ALICE, "Alice");
        createVerifiedUser(BOB, "Bob");
        String token = login(ALICE, PASSWORD).path("token").asText();
        String[] parts = token.split("\\.");
        JsonNode claims = mapper.readTree(Base64.getUrlDecoder().decode(parts[1]));
        ((com.fasterxml.jackson.databind.node.ObjectNode) claims).put("sub", "2");
        String alteredPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(mapper.writeValueAsBytes(claims));
        String tampered = parts[0] + "." + alteredPayload + "." + parts[2];
        char replacement = parts[2].charAt(0) == 'A' ? 'B' : 'A';
        String tamperedSignature = parts[0] + "." + parts[1] + "." + replacement + parts[2].substring(1);
        String unsignedHeader = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String unsigned = unsignedHeader + "." + alteredPayload + ".";

        for (String invalid : new String[] {tampered, tamperedSignature, unsigned, "not-a-jwt"}) {
            mockMvc.perform(get("/api/users/2").header("Authorization", "Bearer " + invalid))
                    .andExpect(status().isUnauthorized());
        }
        mockMvc.perform(get("/api/users/1").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    void expiredAndWrongAudienceTokensCannotAccessProfile() throws Exception {
        createVerifiedUser(ALICE, "Alice");
        String token = login(ALICE, PASSWORD).path("token").asText();
        int version = JWT.decode(token).getClaim("version").asInt();
        String expired = JWT.create().withIssuer("user-manager").withAudience("user-api")
                .withSubject("1").withClaim("version", version)
                .withExpiresAt(new Date(System.currentTimeMillis() - 60_000))
                .sign(Algorithm.HMAC256(SECRET));
        String wrongAudience = JWT.create().withIssuer("user-manager").withAudience("another-api")
                .withSubject("1").withClaim("version", version)
                .withExpiresAt(new Date(System.currentTimeMillis() + 60_000))
                .sign(Algorithm.HMAC256(SECRET));
        for (String invalid : new String[] {expired, wrongAudience}) {
            mockMvc.perform(get("/api/users/1").header("Authorization", "Bearer " + invalid))
                    .andExpect(status().isUnauthorized());
        }
        mockMvc.perform(get("/api/users/1").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    void tokensWithMissingOrIncorrectSecurityClaimsCannotAccessProfile() throws Exception {
        createVerifiedUser(ALICE, "Alice");
        String valid = login(ALICE, PASSWORD).path("token").asText();
        int version = JWT.decode(valid).getClaim("version").asInt();
        Date future = new Date(System.currentTimeMillis() + 60_000);
        String wrongIssuer = JWT.create().withIssuer("other-issuer").withAudience("user-api")
                .withSubject("1").withClaim("version", version).withExpiresAt(future)
                .sign(Algorithm.HMAC256(SECRET));
        String noExpiry = JWT.create().withIssuer("user-manager").withAudience("user-api")
                .withSubject("1").withClaim("version", version).sign(Algorithm.HMAC256(SECRET));
        String noVersion = JWT.create().withIssuer("user-manager").withAudience("user-api")
                .withSubject("1").withExpiresAt(future).sign(Algorithm.HMAC256(SECRET));
        String wrongVersion = JWT.create().withIssuer("user-manager").withAudience("user-api")
                .withSubject("1").withClaim("version", version + 1).withExpiresAt(future)
                .sign(Algorithm.HMAC256(SECRET));
        mockMvc.perform(get("/api/users/1").header("Authorization", "Bearer " + wrongIssuer))
                .andExpect(status().isUnauthorized());
        for (String invalid : new String[] {noExpiry, noVersion, wrongVersion}) {
            mockMvc.perform(get("/api/users/1").header("Authorization", "Bearer " + invalid))
                    .andExpect(status().isForbidden());
        }
        mockMvc.perform(get("/api/users/1").header("Authorization", "Bearer " + valid))
                .andExpect(status().isOk());
    }

    @Test
    void alteredAndExpiredRecoveryCodesCannotChangePassword() throws Exception {
        createVerifiedUser(ALICE, "Alice");
        postJson("/api/users/password-reset/request", Map.of("email", ALICE))
                .andExpect(status().isAccepted());
        String code = sender.codes.get(1);
        char replacement = code.charAt(0) == 'A' ? 'B' : 'A';
        String altered = replacement + code.substring(1);
        postJson("/api/users/password-reset", Map.of(
                "email", ALICE, "newPassword", ATTACKER_PASSWORD, "resetToken", altered))
                .andExpect(status().isForbidden());
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate("UPDATE email_codes SET expires_at = 0 WHERE purpose = 'recovery'");
        }
        postJson("/api/users/password-reset", Map.of(
                "email", ALICE, "newPassword", ATTACKER_PASSWORD, "resetToken", code))
                .andExpect(status().isForbidden());
        postJson("/api/users/authenticate", Map.of("email", ALICE, "password", ATTACKER_PASSWORD))
                .andExpect(status().isUnauthorized());
        assertEquals(ALICE, login(ALICE, PASSWORD).path("user").path("email").asText());
    }

    @Test
    void credentialsAndInternalTokenStateAreNotReturnedByApi() throws Exception {
        createVerifiedUser(ALICE, "Alice");
        JsonNode authentication = login(ALICE, PASSWORD);
        JsonNode user = authentication.path("user");
        assertFalse(user.has("password"));
        assertFalse(user.has("token_version"));
        String body = mockMvc.perform(get("/api/users/1")
                        .header("Authorization", "Bearer " + authentication.path("token").asText()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        JsonNode profile = mapper.readTree(body);
        assertFalse(profile.has("password"));
        assertFalse(profile.has("token_version"));
    }

    @Test
    void recoveredAccountRejectsOldAccessTokenAndReplayedRecoveryCode() throws Exception {
        createVerifiedUser(ALICE, "Alice");
        String oldToken = login(ALICE, PASSWORD).path("token").asText();
        postJson("/api/users/password-reset/request", Map.of("email", ALICE))
                .andExpect(status().isAccepted());
        String code = sender.codes.get(1);
        Map<String, String> reset = Map.of("email", ALICE, "newPassword", ATTACKER_PASSWORD, "resetToken", code);
        postJson("/api/users/password-reset", reset).andExpect(status().isOk());
        postJson("/api/users/password-reset", reset).andExpect(status().isForbidden());
        mockMvc.perform(get("/api/users/1").header("Authorization", "Bearer " + oldToken))
                .andExpect(status().isForbidden());
        JsonNode newLogin = login(ALICE, ATTACKER_PASSWORD);
        assertFalse(newLogin.path("user").has("password"));
        mockMvc.perform(get("/api/users/1").header("Authorization", "Bearer " + newLogin.path("token").asText()))
                .andExpect(status().isOk());
    }

    private void createVerifiedUser(String email, String info) throws Exception {
        int codeIndex = sender.codes.size();
        postJson("/api/users/register", Map.of("email", email, "personalInfo", info))
                .andExpect(status().isAccepted());
        verify(email, PASSWORD, sender.codes.get(codeIndex)).andExpect(status().isOk());
    }

    private ResultActions verify(String email, String password, String code) throws Exception {
        return postJson("/api/users/verify", Map.of("email", email, "password", password, "code", code));
    }

    private JsonNode login(String email, String password) throws Exception {
        String body = postJson("/api/users/authenticate", Map.of("email", email, "password", password))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return mapper.readTree(body);
    }

    private ResultActions postJson(String path, Map<String, String> body) throws Exception {
        return mockMvc.perform(post(path).contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(body)));
    }

    private ResultActions postFrom(String path, Map<String, String> body, String ip) throws Exception {
        return mockMvc.perform(post(path).with(request -> {
            request.setRemoteAddr(ip);
            return request;
        }).contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(body)));
    }
}
