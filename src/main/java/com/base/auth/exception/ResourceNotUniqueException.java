package com.base.auth.exception;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ResourceNotUniqueException extends RuntimeException {

    String resourceName;
    String fieldName;
    String fieldValue;

    public ResourceNotUniqueException(String resourceName, String fieldName, String fieldValue) {
        super(String.format("%s not unique with %s: %s", resourceName, fieldName, fieldValue));
        this.resourceName = resourceName;
        this.fieldName = fieldName;
        this.fieldValue = fieldValue;
    }
}
