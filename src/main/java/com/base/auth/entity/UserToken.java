package com.base.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "password_reset_tokens")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserToken {

    @Id
    @GeneratedValue
    private UUID id;

    @Column(nullable = false, unique = true)
    private String token;

    @Column(nullable = false)
    private String userId;

    @Column(nullable = false)
    private Instant expiryDate;

    @Column(nullable = false)
    private boolean revoked = false;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TokenType type;

    @Column(nullable = false, updatable = false)
    private Instant createdOn = Instant.now();

    @PrePersist
    protected void onCreate() {
        this.createdOn = Instant.now();
    }
}

