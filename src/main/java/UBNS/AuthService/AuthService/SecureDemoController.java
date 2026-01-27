package UBNS.AuthService.AuthService;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecureDemoController {

    @GetMapping("/secure")
    @PreAuthorize("hasRole('ADMIN')")
    public String secureEndpoint() {
        return "Du bist ADMIN und authentifiziert 🎉";
    }
}
