package com.base.auth.exception;

import com.base.auth.dto.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<?>> handleException(Exception ex) {
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error(ex.getMessage()));
    }

    @ExceptionHandler(ResourceNotUniqueException.class)
    public ResponseEntity<ApiResponse<?>> handleResourceNotUnique(ResourceNotUniqueException ex) {
        return ResponseEntity
                .status(HttpStatus.CONFLICT) // better semantic than BAD_REQUEST
                .body(ApiResponse.error(ex.getMessage()));
    }
}
