package com.base.auth.repository;

import com.base.auth.entity.TokenType;
import com.base.auth.entity.UserToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserTokenRepository extends JpaRepository<UserToken, UUID> {

    Optional<UserToken> findByTokenAndType(String token, TokenType type);

    void deleteByUserIdAndType(String userId, TokenType type);
}

