package lab3.exemplar;

import com.auth0.jwt.exceptions.JWTVerificationException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final UserManager userManager;

    public UserController(UserManager userManager) {
        this.userManager = userManager;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@Valid @RequestBody RegisterRequest request) {
        String result = userManager.registerUser(request.email(), request.password(), request.personalInfo());
        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<Map<String, Object>> authenticate(@Valid @RequestBody AuthenticationRequest request) {
        Map<String, Object> authentication = userManager.authenticateUser(request.email(), request.password());
        if (authentication == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("token", authentication.get("token"));
        response.put("user", withoutPassword((Map<?, ?>) authentication.get("user")));
        return ResponseEntity.ok(response);
    }

    @PostMapping("/password-reset")
    public ResponseEntity<String> resetPassword(@Valid @RequestBody PasswordResetRequest request) {
        return ResponseEntity.ok(
                userManager.resetPassword(request.email(), request.newPassword(), request.resetToken()));
    }

    @GetMapping("/{userId}")
    public ResponseEntity<Map<String, Object>> getUser(
            @PathVariable("userId") String userId,
            @RequestHeader(value = "Authorization", required = false) String authorization) {
        String token = bearerToken(authorization);
        if (token == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Map<String, Object> user = userManager.getUserDataForToken(userId, token);
        if (user == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(withoutPassword(user));
    }

    @ExceptionHandler(JWTVerificationException.class)
    ResponseEntity<Void> invalidToken() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    @ExceptionHandler(SecurityException.class)
    ResponseEntity<Void> forbidden() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<Map<String, String>> invalidRequest() {
        return ResponseEntity.badRequest().body(Map.of("error", "Invalid request"));
    }

    private static String bearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return null;
        }
        String token = authorization.substring("Bearer ".length()).trim();
        return token.isEmpty() ? null : token;
    }

    private static Map<String, Object> withoutPassword(Map<?, ?> user) {
        Map<String, Object> safeUser = new LinkedHashMap<>();
        user.forEach((key, value) -> {
            if (key instanceof String stringKey) {
                safeUser.put(stringKey, value);
            }
        });
        safeUser.remove("password");
        return safeUser;
    }

    public record RegisterRequest(
            @NotBlank @Email String email,
            @NotBlank String password,
            @NotNull String personalInfo) {
    }

    public record AuthenticationRequest(
            @NotBlank @Email String email,
            @NotBlank String password) {
    }

    public record PasswordResetRequest(
            @NotBlank @Email String email,
            @NotBlank String newPassword,
            @NotBlank String resetToken) {
    }
}
