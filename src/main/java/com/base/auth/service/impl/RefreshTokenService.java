package com.base.auth.service.impl;

import com.base.auth.entity.RefreshToken;
import com.base.auth.repository.RefreshTokenRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    public RefreshToken createRefreshToken(String userId) {
        String token = UUID.randomUUID().toString(); // or JWT if you prefer
        RefreshToken refreshToken = RefreshToken.builder()
                .userId(userId)
                .token(token)
                .expiryDate(Instant.now().plusSeconds(7 * 24 * 60 * 60))
                .revoked(false)
                .build();
        return refreshTokenRepository.save(refreshToken);
    }

    public boolean revokeToken(String token) {
        return refreshTokenRepository.findByToken(token)
                .map(t -> {
                    t.setRevoked(true);
                    refreshTokenRepository.save(t);
                    return true;
                }).orElse(false);
    }

//    public boolean isValid(String token) {
//        return refreshTokenRepository.findByToken(token)
//                .filter(t -> !t.isRevoked() && t.getExpiryDate().isAfter(Instant.now()))
//                .isPresent();
//    }

    public Optional<RefreshToken> findByToken(String refreshToken) {
        return refreshTokenRepository.findByToken(refreshToken);
    }

    @Transactional
    public void deleteAllToken(String userId) {
        refreshTokenRepository.deleteByUserId(userId);
    }
}

