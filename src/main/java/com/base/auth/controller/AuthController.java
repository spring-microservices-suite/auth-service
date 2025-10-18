package com.base.auth.controller;

import com.base.auth.dto.ApiResponse;
import com.base.auth.dto.LoginRequest;
import com.base.auth.dto.UserDto;
import com.base.auth.entity.RefreshToken;
import com.base.auth.exception.ResourceNotFoundException;
import com.base.auth.repository.UserRepository;
import com.base.auth.security.JwtService;
import com.base.auth.service.UserService;
import com.base.auth.service.impl.PasswordResetService;
import com.base.auth.service.impl.RefreshTokenService;
import com.base.auth.util.SecurityUtil;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import com.base.auth.dto.AuthResponse;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class AuthController {

    @Autowired
    UserRepository userRepo;

    @Autowired
    JwtService jwtService;

    @Autowired
    UserService userService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    RefreshTokenService refreshTokenService;

    @Autowired
    SecurityUtil securityUtil;

    @Autowired
    PasswordResetService resetService;


    @PostMapping("/auth/register")
    public ResponseEntity<ApiResponse<UserDto>> createUser(@Valid @RequestBody UserDto userDto) {
        Map<String, Object> requestMap = new HashMap<>();
        requestMap.put("user", userDto);
        UserDto createdUserDto = this.userService.registerUser(requestMap);
        return ResponseEntity.ok(ApiResponse.success(createdUserDto));
    }

    @PutMapping("/users/{userId}")
    public ResponseEntity<ApiResponse<UserDto>> updateUser(@Valid @RequestBody UserDto userDto, @PathVariable String userId) {

        if (!securityUtil.isSelfOrAdmin(userId)) {
            throw new AccessDeniedException("Unauthorized");
        }

        Map<String, Object> requestMap = new HashMap<>();
        requestMap.put("user", userDto);
        requestMap.put("userId", userId);
        UserDto updatedUserDto = this.userService.updateUser(requestMap);
        return ResponseEntity.ok(ApiResponse.success(updatedUserDto));
    }

    @DeleteMapping("/users/{userId}")
    public ResponseEntity<ApiResponse<String>> deleteUser(@PathVariable String userId) {

        if (!securityUtil.isSelfOrAdmin(userId)) {
            throw new AccessDeniedException("Unauthorized");
        }

        Map<String, Object> requestMap = new HashMap<>();
        requestMap.put("userId", userId);
        this.userService.deleteUser(requestMap);
        return ResponseEntity.ok(ApiResponse.success("User deleted successfully"));
    }

    @GetMapping("/users/{userId}")
    public ResponseEntity<ApiResponse<UserDto>> getUser(@PathVariable("userId") String uid) {
        Map<String, Object> requestMap = new HashMap<>();
        requestMap.put("userId", uid);
        return ResponseEntity.ok(ApiResponse.success(this.userService.getUser(requestMap)));
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<UserDto>>> getAllUsers() {
        return ResponseEntity.ok(ApiResponse.success(this.userService.getAllUsers()));
    }

    @PostMapping("/auth/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(@RequestBody LoginRequest req) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getEmailId(), req.getPassword())
        );
        var user = userRepo.findByEmailId(req.getEmailId()).orElseThrow();
        String accessToken = jwtService.generateAccessToken(user.getEmailId(), user.getRole().name());
        Instant accessTokenExpiry = jwtService.extractExpiration(accessToken);

        RefreshToken refreshTokenEntity = refreshTokenService.createRefreshToken(user.getUserId());

        AuthResponse tokens = new AuthResponse(accessToken, refreshTokenEntity.getToken(), accessTokenExpiry, refreshTokenEntity.getExpiryDate());
        return ResponseEntity.ok(ApiResponse.success(tokens));
    }

    @Transactional
    @PostMapping("/auth/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refresh(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");

        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error("Refresh token is required"));
        }

        // Check DB for refresh token validity
        RefreshToken tokenEntity = refreshTokenService.findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Invalid or expired refresh token"));

        if (tokenEntity.isRevoked() || tokenEntity.getExpiryDate().isBefore(Instant.now())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Invalid, expired, or revoked refresh token"));
        }

        var user = userRepo.findByUserId(tokenEntity.getUserId())
                .orElseThrow(() -> new ResourceNotFoundException("User", "UserId", tokenEntity.getUserId()));

        // Generate new access token
        String newAccessToken = jwtService.generateAccessToken(user.getEmailId(), user.getRole().name());
        Instant accessTokenExpiry = jwtService.extractExpiration(newAccessToken);
        refreshTokenService.revokeToken(refreshToken);
        RefreshToken newRefressToken = refreshTokenService.createRefreshToken(user.getUserId());
        AuthResponse tokens = new AuthResponse(newAccessToken, newRefressToken.getToken(), accessTokenExpiry, newRefressToken.getExpiryDate());
        return ResponseEntity.ok(ApiResponse.success(tokens));
    }

    @PostMapping("/users/logout")
    public ResponseEntity<ApiResponse<String>> logout(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");

        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error("Refresh token is required"));
        }

        boolean revoked = refreshTokenService.revokeToken(refreshToken);

        if (!revoked) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error("Invalid or already revoked refresh token"));
        }

        return ResponseEntity.ok(ApiResponse.success("Logged out successfully"));
    }

    @PostMapping("/users/all/logout")
    public ResponseEntity<ApiResponse<String>> logoutFromAll(@RequestBody Map<String, String> request) {
        String userId = request.get("userId");

        if (!securityUtil.isSelfOrAdmin(userId)) {
            throw new AccessDeniedException("Unauthorized");
        }

        if (userId == null || userId.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error("userId is required"));
        }
        refreshTokenService.deleteAllToken(userId);
        return ResponseEntity.ok(ApiResponse.success("Logged out successfully from all sessions"));
    }

    @PostMapping("/auth/forgot-password")
    public ResponseEntity<ApiResponse<String>> forgotPassword(@RequestBody Map<String, String> req) {
        String emailId = req.get("emailId");
        resetService.createResetToken(emailId);
        return ResponseEntity.ok(ApiResponse.success(
                "If the emailId exists, a reset link has been generated (check backend logs)."
        ));
    }

    // Reset password
    @PostMapping("/auth/reset-password")
    public ResponseEntity<ApiResponse<String>> resetPassword(@RequestBody Map<String, String> req) {
        String token = req.get("token");
        String newPassword = req.get("newPassword");
        resetService.resetPassword(token, newPassword);
        return ResponseEntity.ok(ApiResponse.success("Password reset successfully"));
    }

}
