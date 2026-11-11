package lab3.exemplar;

import com.auth0.jwt.exceptions.JWTVerificationException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
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
        String result = userManager.registerUser(request.email(), request.personalInfo());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(result);
    }

    @PostMapping("/verify")
    public ResponseEntity<String> verify(@Valid @RequestBody VerificationRequest request) {
        return ResponseEntity.ok(userManager.verifyEmail(request.email(), request.password(), request.code()));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<Map<String, Object>> authenticate(@Valid @RequestBody AuthenticationRequest request,
            HttpServletRequest servletRequest) {
        Map<String, Object> authentication = userManager.authenticateUser(
                request.email(), request.password(), servletRequest.getRemoteAddr());
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

    @PostMapping("/password-reset/request")
    public ResponseEntity<String> requestReset(@Valid @RequestBody ResetRequest request) {
        return ResponseEntity.accepted().body(userManager.requestPasswordReset(request.email()));
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

    @ExceptionHandler(IllegalArgumentException.class)
    ResponseEntity<Map<String, String>> invalidArgument() {
        return ResponseEntity.badRequest().body(Map.of("error", "Invalid request"));
    }

    @ExceptionHandler(RateLimitException.class)
    ResponseEntity<Map<String, String>> rateLimited() {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", "900")
                .body(Map.of("error", "Too many authentication attempts"));
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
        safeUser.remove("token_version");
        return safeUser;
    }

    public record RegisterRequest(
            @NotBlank @Email @Size(max = 254) String email,
            @NotNull @Size(max = 2000) String personalInfo) {
    }

    public record VerificationRequest(
            @NotBlank @Email @Size(max = 254) String email,
            @NotBlank @Size(min = 12, max = 128) String password,
            @NotBlank @Size(max = 43) String code) {
    }

    public record ResetRequest(@NotBlank @Email @Size(max = 254) String email) {
    }

    public record AuthenticationRequest(
            @NotBlank @Email @Size(max = 254) String email,
            @NotBlank @Size(max = 128) String password) {
    }

    public record PasswordResetRequest(
            @NotBlank @Email @Size(max = 254) String email,
            @NotBlank @Size(min = 12, max = 128) String newPassword,
            @NotBlank @Size(max = 43) String resetToken) {
    }
}
