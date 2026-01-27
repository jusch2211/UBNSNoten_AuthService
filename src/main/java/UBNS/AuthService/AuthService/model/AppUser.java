package UBNS.AuthService.AuthService.model;

public record AppUser(
        String username,
        String passwordHash,
        String role
) {}
