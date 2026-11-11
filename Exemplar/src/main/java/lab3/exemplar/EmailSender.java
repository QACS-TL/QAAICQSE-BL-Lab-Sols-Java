package lab3.exemplar;

@FunctionalInterface
public interface EmailSender {
    void sendCode(String email, String purpose, String code);
}
