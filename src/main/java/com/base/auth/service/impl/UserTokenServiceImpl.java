package com.base.auth.service.impl;

import com.base.auth.entity.TokenType;
import com.base.auth.entity.User;
import com.base.auth.entity.UserToken;
import com.base.auth.exception.ResourceNotFoundException;
import com.base.auth.repository.UserRepository;
import com.base.auth.repository.UserTokenRepository;
import com.base.auth.service.UserTokenService;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
public class UserTokenServiceImpl implements UserTokenService {

    @Autowired
    private UserTokenRepository userTokenRepository;

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public UserToken createToken(String identifier, TokenType type) {
        String token = UUID.randomUUID().toString(); // or JWT if you prefer
        if (type.name().equals("REFRESH")) {
            UserToken userToken = UserToken.builder()
                    .userId(identifier)
                    .token(token)
                    .type(type)
                    .expiryDate(Instant.now().plusSeconds(7 * 24 * 60 * 60))
                    .revoked(false)
                    .build();
            return userTokenRepository.save(userToken);
        } else {
            var user = userRepo.findByEmailId(identifier)
                    .orElseThrow(() -> new ResourceNotFoundException("User", "id", identifier));
            UserToken userToken = UserToken.builder()
                    .userId(user.getUserId())
                    .token(token)
                    .type(type)
                    .expiryDate(Instant.now().plus(1, ChronoUnit.HOURS))
                    .revoked(false)
                    .build();

            userTokenRepository.save(userToken);

            // For backend-only testing, log the link
            System.out.println("Reset password link: http://localhost:8080/auth/reset-password?token=" + token);
            return userToken;
        }
    }

    public UserToken validateAndRevokeToken(String token, TokenType type) {
        UserToken userToken = userTokenRepository.findByTokenAndType(token, type)
                .orElseThrow(() -> new RuntimeException("Invalid token"));

        if (userToken.isRevoked() || userToken.getExpiryDate().isBefore(Instant.now())) {
            throw new RuntimeException("Token expired or already used");
        }
        userToken.setRevoked(true);
        return userTokenRepository.save(userToken);
    }

    @Transactional
    public void deleteAllToken(String userId, TokenType type) {
        userTokenRepository.deleteByUserIdAndType(userId, type);
    }

    public User fetchUserFromToken(String token, TokenType type) {
        UserToken userToken = validateAndRevokeToken(token, type);
        return userRepo.findByUserId(userToken.getUserId())
                .orElseThrow(() -> new ResourceNotFoundException("User", "userId", userToken.getUserId()));
    }

    // Reset password using token
    public void resetPassword(String token, String newPassword, TokenType type) {
        User user = fetchUserFromToken(token, type);
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepo.save(user);
    }

    // Verify email using token
    public void verifyEmail(String token, TokenType type) {
        User user = fetchUserFromToken(token, type);
        user.setActive(true);
        userRepo.save(user);
    }
}