package com.lykup.authservice.service;

import com.lykup.authservice.dto.LoginRequest;
import com.lykup.authservice.dto.LoginResponse;
import com.lykup.authservice.dto.SignupRequest;
import com.lykup.authservice.entity.User;
import com.lykup.authservice.repository.UserRepository;
import com.lykup.authservice.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public void registerUser(SignupRequest request) {
        if (userRepository.existsByEmail(request.getEmail()))
            throw new RuntimeException("Email already exists");

        if (userRepository.existsByUsername(request.getUsername()))
            throw new RuntimeException("Username already exists");

        User user = User.builder()
                .email(request.getEmail())
                .username(request.getUsername())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .build();

        userRepository.save(user);
    }

    public LoginResponse authenticateUser(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash()))
            throw new RuntimeException("Invalid password");

        String token = jwtUtil.generateToken(user.getId().toString(), user.getUsername());
        return new LoginResponse(token, user.getId().toString(), user.getUsername());
    }
}
