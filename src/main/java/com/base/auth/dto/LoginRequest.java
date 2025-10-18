package com.base.auth.dto;

import lombok.*;

@Data // generates getters, setters, toString, equals, hashCode
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {
    private String emailId;
    private String password;
}