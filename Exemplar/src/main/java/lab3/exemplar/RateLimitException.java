package lab3.exemplar;

public class RateLimitException extends RuntimeException {
    public RateLimitException() {
        super("Too many authentication attempts");
    }
}
