package com.omalley.login_auth_api.controllers;

import com.omalley.login_auth_api.domain.user.User;
import com.omalley.login_auth_api.dto.LoginRequestDTO;
import com.omalley.login_auth_api.dto.RegisterRequestDTO;
import com.omalley.login_auth_api.dto.ResponseDTO;
import com.omalley.login_auth_api.infra.security.TokenService;
import com.omalley.login_auth_api.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor

public class AuthController {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginRequestDTO body) {
        User user = this.repository.findByEmail(body.email()).orElseThrow(() -> new RuntimeException("User not found"));
        if(passwordEncoder.matches(body.password(), user.getPassword())) {
            String token = this.tokenService.generateToken(user);
            return ResponseEntity.ok(new ResponseDTO(user.getName(), token));
        }
        return ResponseEntity.badRequest().build();
    }

    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegisterRequestDTO body) {
        Optional<User> user = this.repository.findByEmail(body.email());
        if(user.isEmpty()) {
            User newUser = new User();
            newUser.setPassword(passwordEncoder.encode(body.password()));
            newUser.setEmail(body.email());
            newUser.setName(body.name());
            this.repository.save(newUser);

            String token = this.tokenService.generateToken(newUser);
            return ResponseEntity.ok(new ResponseDTO(newUser.getName(), token));
        }
        return ResponseEntity.badRequest().build();
    }



    @GetMapping("/token/info")
    public ResponseEntity<Map<String, Object>> getTokenInfo(
            @RequestHeader("Authorization") String authHeader) {
        try {
            String token = authHeader.replace("Bearer ", "");

            long remainingSeconds = tokenService.getRemainingTimeInSeconds(token);

            if (remainingSeconds < 0) {
                return ResponseEntity.status(401)
                        .body(Map.of("error", "Invalid token"));
            }

            Map<String, Object> info = new HashMap<>();
            info.put("remainingSeconds", remainingSeconds);
            info.put("valid", true);

            return ResponseEntity.ok(info);
        } catch (Exception e) {
            return ResponseEntity.status(401)
                    .body(Map.of("error", "Invalid token"));
        }
    }
}
