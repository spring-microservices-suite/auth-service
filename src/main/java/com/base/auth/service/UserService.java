package com.base.auth.service;

import com.base.auth.dto.UserDto;

import java.util.List;
import java.util.Map;

public interface UserService {

    UserDto registerUser(Map<String, Object> requestMap);

    UserDto updateUser(Map<String, Object> requestMap);

    UserDto getUser(Map<String, Object> requestMap);

    List<UserDto> getAllUsers();

    void deleteUser(Map<String, Object> requestMap);
}
