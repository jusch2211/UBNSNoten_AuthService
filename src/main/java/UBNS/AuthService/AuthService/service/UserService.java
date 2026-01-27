package UBNS.AuthService.AuthService.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import UBNS.AuthService.AuthService.model.AppUser;

import java.util.List;

@Service
public class UserService {

    private final PasswordEncoder encoder = new BCryptPasswordEncoder();

    private final List<AppUser> users = List.of(
            new AppUser("admin", encoder.encode("admin123"), "ADMIN"),
            new AppUser("user", encoder.encode("user123"), "USER")
    );

    public AppUser authenticate(String username, String password) {
        return users.stream()
                .filter(u -> u.username().equals(username))
                .filter(u -> encoder.matches(password, u.passwordHash()))
                .findFirst()
                .orElse(null);
    }
}
