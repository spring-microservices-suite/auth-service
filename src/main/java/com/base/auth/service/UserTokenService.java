package com.base.auth.service;

import com.base.auth.entity.TokenType;
import com.base.auth.entity.User;
import com.base.auth.entity.UserToken;

public interface UserTokenService {

    UserToken createToken(String userId, TokenType type);

    User fetchUserFromToken(String token, TokenType type);

    void deleteAllToken(String userId, TokenType type);

    void resetPassword(String token, String newPassword, TokenType type);

    void verifyEmail(String token, TokenType type);

    UserToken validateAndRevokeToken(String token, TokenType type);
}