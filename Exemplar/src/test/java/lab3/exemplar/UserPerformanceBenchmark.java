package lab3.exemplar;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.annotation.DirtiesContext;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "app.jwt.secret=performance-test-only-key-not-for-production",
        "app.mail.from=test@example.com",
        "spring.mail.host=localhost",
        "server.address=127.0.0.1"
})
@Import(UserControllerTest.FakeMailConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class UserPerformanceBenchmark {
    private static final int CLIENTS = 20;
    private static final String EMAIL = "benchmark0@example.com";
    private static final String PASSWORD = "benchmark-password";

    @TempDir
    static Path databaseDirectory;

    @DynamicPropertySource
    static void databaseProperty(DynamicPropertyRegistry registry) {
        registry.add("app.database.url", () -> "jdbc:sqlite:" + databaseDirectory.resolve("benchmark.db"));
    }

    @LocalServerPort private int port;
    @Autowired private Connection connection;
    @Autowired private ObjectMapper mapper;
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @BeforeAll
    static void describeRun() {
        System.out.printf("Performance workload: %d simultaneous clients; Java %s; %d available processors%n",
                CLIENTS, System.getProperty("java.version"), Runtime.getRuntime().availableProcessors());
    }

    @Test
    void securedLoginAndProfileMeetLocalPerformanceTargets() throws Exception {
        try (PreparedStatement insert = connection.prepareStatement(
                "INSERT INTO users (email, password, info, email_verified) VALUES (?, ?, ?, 1)")) {
            for (int i = 0; i < CLIENTS; i++) {
                insert.setString(1, "benchmark" + i + "@example.com");
                insert.setString(2, PasswordHasher.hash(PASSWORD));
                insert.setString(3, "Benchmark user");
                insert.executeUpdate();
            }
        }

        List<HttpRequest> logins = new ArrayList<>();
        for (int i = 0; i < CLIENTS; i++) {
            logins.add(HttpRequest.newBuilder(uri("/api/users/authenticate"))
                    .timeout(Duration.ofSeconds(30))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(
                            java.util.Map.of("email", "benchmark" + i + "@example.com", "password", PASSWORD))))
                    .build());
        }

        String token = null;
        for (int i = 0; i < 3; i++) {
            HttpResponse<String> warmup = client.send(logins.get(0), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, warmup.statusCode(), warmup.body());
            token = mapper.readTree(warmup.body()).path("token").asText();
        }
        assertFalse(token.isBlank());

        Result loginResult = runWorkload(logins, CLIENTS, true);
        HttpRequest profile = HttpRequest.newBuilder(uri("/api/users/1"))
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", "Bearer " + token)
                .GET().build();
        for (int i = 0; i < 10; i++) {
            HttpResponse<String> warmup = client.send(profile, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, warmup.statusCode(), warmup.body());
        }
        Result profileResult = runWorkload(List.of(profile), 100, false);

        report("Login", loginResult);
        report("Profile", profileResult);
        assertAll(
                () -> assertEquals(0, loginResult.errors(), "Every login must succeed without throttling"),
                () -> assertEquals(0, profileResult.errors(), "Every authenticated profile request must succeed"),
                () -> assertTrue(loginResult.p95Millis() <= 2000, "Login p95 must not exceed 2000 ms"),
                () -> assertTrue(profileResult.p95Millis() <= 500, "Profile p95 must not exceed 500 ms"));
    }

    @Test
    void measureParallelPasswordVerificationCapacity() throws Exception {
        String hash = PasswordHasher.hash(PASSWORD);
        ExecutorService workers = Executors.newFixedThreadPool(CLIENTS);
        CountDownLatch ready = new CountDownLatch(CLIENTS);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Long>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < CLIENTS; i++) {
                futures.add(workers.submit(() -> {
                    ready.countDown();
                    start.await();
                    long begin = System.nanoTime();
                    if (!PasswordHasher.matches(PASSWORD, hash)) {
                        throw new IllegalStateException("Password verification failed");
                    }
                    return System.nanoTime() - begin;
                }));
            }
            ready.await();
            long begin = System.nanoTime();
            start.countDown();
            long[] times = new long[CLIENTS];
            for (int i = 0; i < CLIENTS; i++) {
                times[i] = futures.get(i).get();
            }
            long elapsed = System.nanoTime() - begin;
            Arrays.sort(times);
            report("Parallel bcrypt only", new Result(times, elapsed, 0));
        } finally {
            workers.shutdownNow();
        }
    }

    private URI uri(String path) {
        return URI.create("http://127.0.0.1:" + port + path);
    }

    private Result runWorkload(List<HttpRequest> inputs, int requests, boolean login) throws Exception {
        ExecutorService workers = Executors.newFixedThreadPool(CLIENTS);
        CountDownLatch ready = new CountDownLatch(CLIENTS);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Sample>> futures = new ArrayList<>();
        try {
            for (int worker = 0; worker < CLIENTS; worker++) {
                final int count = requests / CLIENTS + (worker < requests % CLIENTS ? 1 : 0);
                final HttpRequest request = inputs.get(worker % inputs.size());
                futures.add(workers.submit(() -> {
                    ready.countDown();
                    start.await();
                    long[] durations = new long[count];
                    int errors = 0;
                    for (int i = 0; i < count; i++) {
                        long begin = System.nanoTime();
                        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                        durations[i] = System.nanoTime() - begin;
                        if (response.statusCode() != 200) {
                            errors++;
                        } else {
                            JsonNode body = mapper.readTree(response.body());
                            if (login ? body.path("token").asText().isBlank()
                                    : !EMAIL.equals(body.path("email").asText())) {
                                errors++;
                            }
                        }
                    }
                    return new Sample(durations, errors);
                }));
            }
            ready.await();
            long begin = System.nanoTime();
            start.countDown();
            long[] times = new long[requests];
            int offset = 0;
            int errors = 0;
            for (Future<Sample> future : futures) {
                Sample sample = future.get();
                System.arraycopy(sample.durations(), 0, times, offset, sample.durations().length);
                offset += sample.durations().length;
                errors += sample.errors();
            }
            long elapsed = System.nanoTime() - begin;
            Arrays.sort(times);
            return new Result(times, elapsed, errors);
        } finally {
            workers.shutdownNow();
        }
    }

    private static void report(String name, Result result) {
        double throughput = result.times().length * 1_000_000_000.0 / result.elapsedNanos();
        System.out.printf("%s: requests=%d errors=%d p50=%.1f ms p95=%.1f ms max=%.1f ms throughput=%.2f req/s%n",
                name, result.times().length, result.errors(), result.percentile(0.50),
                result.p95Millis(), result.percentile(1.0), throughput);
    }

    private record Sample(long[] durations, int errors) {
    }

    private record Result(long[] times, long elapsedNanos, int errors) {
        double percentile(double percentile) {
            return times[(int) Math.ceil(percentile * times.length) - 1] / 1_000_000.0;
        }

        double p95Millis() {
            return percentile(0.95);
        }
    }
}
