package UBNS.AuthService.AuthService.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import UBNS.AuthService.AuthService.model.AppUser;
import UBNS.AuthService.AuthService.security.JwtUtil;
import UBNS.AuthService.AuthService.service.UserService;

@RestController
@RequestMapping("/auth")
@CrossOrigin
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;

    public AuthController(UserService userService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {

        AppUser user = userService.authenticate(
                request.username(),
                request.password()
        );

        if (user == null) {
            return ResponseEntity.status(401).build();
        }

        String token = jwtUtil.generateToken(user);
        return ResponseEntity.ok(new LoginResponse(token));
    }
}

record LoginRequest(String username, String password) {}
record LoginResponse(String token) {}
