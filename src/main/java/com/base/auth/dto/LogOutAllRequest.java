package com.base.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data // generates getters, setters, toString, equals, hashCode
@NoArgsConstructor
@AllArgsConstructor
public class LogOutAllRequest {
    @NotBlank(message = "userId is required")
    private String userId;
}