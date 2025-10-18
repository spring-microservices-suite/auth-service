package com.base.auth.service.impl;

import com.base.auth.entity.PasswordResetToken;
import com.base.auth.repository.PasswordResetTokenRepository;
import com.base.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final PasswordResetTokenRepository resetTokenRepo;
    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;

    // Step 1: Generate reset token
    public PasswordResetToken createResetToken(String emailId) {
        var user = userRepo.findByEmailId(emailId)
                .orElseThrow(() -> new RuntimeException("EmailId not found"));

        String token = UUID.randomUUID().toString();
        PasswordResetToken resetToken = PasswordResetToken.builder()
                .userId(user.getUserId())
                .token(token)
                .expiryDate(Instant.now().plus(1, ChronoUnit.HOURS))
                .used(false)
                .build();

        resetTokenRepo.save(resetToken);

        // For backend-only testing, log the link
        System.out.println("Reset password link: http://localhost:8080/auth/reset-password?token=" + token);

        return resetToken;
    }

    // Step 2: Reset password using token
    public void resetPassword(String token, String newPassword) {
        var resetToken = resetTokenRepo.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid or expired token"));

        if (resetToken.isUsed() || resetToken.getExpiryDate().isBefore(Instant.now())) {
            throw new RuntimeException("Token expired or already used");
        }

        var user = userRepo.findByUserId(resetToken.getUserId())
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepo.save(user);

        resetToken.setUsed(true);
        resetTokenRepo.save(resetToken);
    }
}

