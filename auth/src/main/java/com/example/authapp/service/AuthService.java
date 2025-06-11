package com.example.authapp.service;

import com.example.authapp.model.User;
import com.example.authapp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.*;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder encoder;

    @Value("${jwt.secret}")
    private String SECRET_KEY;

    private static final long EXPIRATION_TIME = 3600000; // 1 hour

    public AuthService(UserRepository userRepository, BCryptPasswordEncoder encoder) {
        this.userRepository = userRepository;
        this.encoder = encoder;
    }

    public Map<String, Object> signup(Map<String, String> body) {
        Map<String, Object> response = new HashMap<>();
        String username = body.get("username");
        String email = body.get("email");
        String password = body.get("password");
        String confirmPassword = body.get("confirmPassword");

        if (username == null || email == null || password == null || confirmPassword == null) {
            response.put("error", "All fields are required");
            return response;
        }

        if (!password.equals(confirmPassword)) {
            response.put("error", "Passwords do not match");
            return response;
        }

        if (userRepository.findByEmail(email).isPresent()) {
            response.put("error", "Email already exists");
            return response;
        }

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(encoder.encode(password));

        userRepository.save(user);

        response.put("message", "User created successfully");
        response.put("user", user);
        return response;
    }

    public Map<String, Object> login(Map<String, String> body) {
        Map<String, Object> response = new HashMap<>();

        String identifier = body.get("identifier"); // Can be username or email
        String password = body.get("password");

        if (identifier == null || password == null) {
            response.put("error", "Email/Username and password are required");
            return response;
        }

        Optional<User> userOpt;

        // Check if identifier is likely an email
        if (identifier.contains("@")) {
            userOpt = userRepository.findByEmail(identifier);
        } else {
            userOpt = userRepository.findByUsername(identifier);
        }

        if (userOpt.isEmpty() || !encoder.matches(password, userOpt.get().getPassword())) {
            response.put("error", "Invalid credentials");
            return response;
        }

        User user = userOpt.get();

        // Create JWT token
        Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));

        String token = Jwts.builder()
                .setSubject(user.getUsername())
                .claim("email", user.getEmail())
                .claim("role", user.getRole())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();

        // Return structured user details
        Map<String, Object> userDetails = new HashMap<>();
        userDetails.put("username", user.getUsername());
        userDetails.put("email", user.getEmail());
        userDetails.put("role", user.getRole());

        response.put("message", "Login successful");
        response.put("token", token);
        response.put("user", userDetails);
        return response;
    }
}