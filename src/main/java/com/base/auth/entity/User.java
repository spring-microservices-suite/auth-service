package com.base.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Table(name = "users")
@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    @Id
    private String userId;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String emailId;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private Role role;

    private boolean active = false;

    @Column(nullable = false)
    private LocalDateTime createdOn;

    private LocalDateTime updatedOn;
}

