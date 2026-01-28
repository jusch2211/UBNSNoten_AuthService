package UBNS.AuthService.AuthService.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import UBNS.AuthService.AuthService.security.JwtAuthenticationFilter;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtFilter) {
        this.jwtFilter = jwtFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
            // REST → keine CSRF
            .csrf(csrf -> csrf.disable())
            // CORS für Flutter / Web
            .cors(Customizer.withDefaults())
            // Stateless → keine Session
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // Zugriffskontrolle
            .authorizeHttpRequests(auth -> auth
                // OPTIONS freigeben (Preflight)
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                // Login frei
                .requestMatchers("/login").permitAll()
                // Alle anderen Endpoints erfordern Auth
                .anyRequest().authenticated()
            )
            // JWT-Filter vor UsernamePasswordAuthenticationFilter ausführen
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
