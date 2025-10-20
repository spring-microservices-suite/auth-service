package com.base.auth.controller;

import com.base.auth.dto.*;
import com.base.auth.entity.TokenType;
import com.base.auth.entity.User;
import com.base.auth.entity.UserToken;
import com.base.auth.repository.UserRepository;
import com.base.auth.security.JwtService;
import com.base.auth.service.UserService;
import com.base.auth.service.UserTokenService;
import com.base.auth.util.SecurityUtil;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
@Validated
public class AuthController {

    @Autowired
    UserRepository userRepo;

    @Autowired
    JwtService jwtService;

    @Autowired
    UserService userService;
    @Autowired
    UserTokenService userTokenService;
    @Autowired
    SecurityUtil securityUtil;
    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/auth/register")
    public ResponseEntity<ApiResponse<UserDto>> createUser(@Valid @RequestBody UserDto userDto) {
        Map<String, Object> requestMap = new HashMap<>();
        requestMap.put("user", userDto);
        UserDto createdUserDto = this.userService.registerUser(requestMap);
        return ResponseEntity.ok(ApiResponse.success(createdUserDto));
    }

    @PutMapping("/users/{userId}")
    public ResponseEntity<ApiResponse<UserDto>> updateUser(@Valid @RequestBody UserDto userDto, @PathVariable @NotBlank(message = "userId is required") String userId) {
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
    public ResponseEntity<ApiResponse<String>> deleteUser(@PathVariable @NotBlank(message = "userId is required") String userId) {
        if (!securityUtil.isSelfOrAdmin(userId)) {
            throw new AccessDeniedException("Unauthorized");
        }

        Map<String, Object> requestMap = new HashMap<>();
        requestMap.put("userId", userId);
        this.userService.deleteUser(requestMap);
        return ResponseEntity.ok(ApiResponse.success("User deleted successfully"));
    }

    @GetMapping("/users/{userId}")
    public ResponseEntity<ApiResponse<UserDto>> getUser(@PathVariable @NotBlank(message = "userId is required") String userId) {
        if (!securityUtil.isSelfOrAdmin(userId)) {
            throw new AccessDeniedException("Unauthorized");
        }
        Map<String, Object> requestMap = new HashMap<>();
        requestMap.put("userId", userId);
        return ResponseEntity.ok(ApiResponse.success(this.userService.getUser(requestMap)));
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<UserDto>>> getAllUsers() {
        return ResponseEntity.ok(ApiResponse.success(this.userService.getAllUsers()));
    }

    @PostMapping("/auth/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(@Valid @RequestBody LoginRequest req) {
        var user = userRepo.findByEmailId(req.getEmailId()).orElseThrow();
        if (!user.isActive()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error("Please verify Email"));
        }
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getEmailId(), req.getPassword())
        );
        String accessToken = jwtService.generateAccessToken(user.getUserId(), user.getRole().name());
        Instant accessTokenExpiry = jwtService.extractExpiration(accessToken);

        UserToken refreshTokenEntity = userTokenService.createToken(user.getUserId(), TokenType.REFRESH);

        AuthResponse tokens = new AuthResponse(accessToken, refreshTokenEntity.getToken(), accessTokenExpiry, refreshTokenEntity.getExpiryDate());
        return ResponseEntity.ok(ApiResponse.success(tokens));
    }

    @Transactional
    @PostMapping("/auth/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refresh(@Valid @RequestBody VerifyTokenRequest request) {
        String refreshToken = request.getToken();
        User user = userTokenService.fetchUserFromToken(refreshToken, TokenType.REFRESH);

        String newAccessToken = jwtService.generateAccessToken(user.getUserId(), user.getRole().name());
        Instant accessTokenExpiry = jwtService.extractExpiration(newAccessToken);

        UserToken newRefreshToken = userTokenService.createToken(user.getUserId(), TokenType.REFRESH);
        AuthResponse tokens = new AuthResponse(newAccessToken, newRefreshToken.getToken(), accessTokenExpiry, newRefreshToken.getExpiryDate());

        return ResponseEntity.ok(ApiResponse.success(tokens));
    }

    @PostMapping("/users/logout")
    public ResponseEntity<ApiResponse<String>> logout(@Valid @RequestBody VerifyTokenRequest request) {
        String refreshToken = request.getToken();
        UserToken userToken = userTokenService.validateAndRevokeToken(refreshToken, TokenType.REFRESH);
        return ResponseEntity.ok(ApiResponse.success("Logged out successfully"));
    }

    @PostMapping("/users/all/logout")
    public ResponseEntity<ApiResponse<String>> logoutFromAll(@Valid @RequestBody LogOutAllRequest request) {
        String userId = request.getUserId();
        if (!securityUtil.isSelfOrAdmin(userId)) {
            throw new AccessDeniedException("Unauthorized");
        }
        userTokenService.deleteAllToken(userId, TokenType.REFRESH);
        return ResponseEntity.ok(ApiResponse.success("Logged out successfully from all sessions"));
    }

    @PostMapping("/auth/forgot-password")
    public ResponseEntity<ApiResponse<String>> forgotPassword(@Valid @RequestBody VerifyEmailRequest req) {
        String emailId = req.getEmail();
        userTokenService.createToken(emailId, TokenType.PASSWORD_RESET);
        return ResponseEntity.ok(ApiResponse.success(
                "If the emailId exists, a reset link has been generated (check backend logs)."
        ));
    }

    // Reset password
    @PostMapping("/auth/reset-password")
    public ResponseEntity<ApiResponse<String>> resetPassword(@Valid @RequestBody ResetPassRequest req) {
        String token = req.getToken();
        String newPassword = req.getNewPassword();
        userTokenService.resetPassword(token, newPassword, TokenType.PASSWORD_RESET);
        return ResponseEntity.ok(ApiResponse.success("Password reset successfully"));
    }

    @PostMapping("/auth/send-verification-email")
    public ResponseEntity<ApiResponse<String>> sendVerificationEmail(@Valid @RequestBody VerifyEmailRequest req) {
        String emailId = req.getEmail();
        userTokenService.createToken(emailId, TokenType.EMAIL_VERIFICATION);
        return ResponseEntity.ok(ApiResponse.success(
                "If the emailId exists, a verification link has been generated (check backend logs)."
        ));
    }

    // Verify email
    @PostMapping("/auth/verify-email")
    public ResponseEntity<ApiResponse<String>> verifyEmail(@Valid @RequestBody VerifyTokenRequest req) {
        String token = req.getToken();
        userTokenService.verifyEmail(token, TokenType.EMAIL_VERIFICATION);
        return ResponseEntity.ok(ApiResponse.success("Email verified successfully"));
    }

}