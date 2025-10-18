package com.base.auth.dto;

import com.base.auth.entity.Role;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class UserDto {

    private String userId;
    private String username;
    private String emailId;
    private String password;
    private Role role;
    private LocalDateTime createdOn;
    private LocalDateTime updatedOn;
}
