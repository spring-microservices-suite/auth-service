package com.base.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data // generates getters, setters, toString, equals, hashCode
@NoArgsConstructor
@AllArgsConstructor
public class ResetPassRequest {

    @NotBlank(message = "token is required")
    private String token;
    @NotBlank
    private String newPassword;
}
