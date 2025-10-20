package com.base.auth.dto;

import com.base.auth.entity.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class UserDto {

    private String userId;
    @NotBlank
    private String username;
    @NotBlank
    @Email
    private String emailId;
    @NotBlank
    private String password;
    @NotBlank
    private Role role;
    private LocalDateTime createdOn;
    private LocalDateTime updatedOn;
}
