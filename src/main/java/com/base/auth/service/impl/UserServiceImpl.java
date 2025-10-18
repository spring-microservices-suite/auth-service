package com.base.auth.service.impl;

import com.base.auth.dto.UserDto;
import com.base.auth.entity.User;
import com.base.auth.exception.ResourceNotFoundException;
import com.base.auth.repository.UserRepository;
import com.base.auth.service.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.base.auth.exception.ResourceNotUniqueException;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    UserRepository userRepo;

    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(ModelMapper modelMapper, PasswordEncoder passwordEncoder) {
        this.modelMapper = modelMapper;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDto registerUser(Map<String, Object> requestMap) {
        UserDto userDto = (UserDto) requestMap.get("user");
        Optional<User> uniqueUser = this.userRepo.findByUsername(userDto.getUsername());
        if (uniqueUser.isPresent()) throw new ResourceNotUniqueException("User", "username", userDto.getUsername());
        User user = modelMapper.map(userDto, User.class);
        UUID id = UUID.randomUUID();
        long n = (id.getLeastSignificantBits() ^ id.getMostSignificantBits()) & Long.MAX_VALUE;
        user.setUserId("US." + n);
        user.setPassword(this.passwordEncoder.encode(user.getPassword()));
        Date date = new Date();
        LocalDateTime localDateTime = date.toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();
        user.setCreatedOn(localDateTime);
        User savedUser = userRepo.save(user);
        return this.modelMapper.map(savedUser, UserDto.class);
    }

    @Override
    public UserDto updateUser(Map<String, Object> requestMap) {
        UserDto userDto = (UserDto) requestMap.get("user");
        String userId = (String) requestMap.get("userId");
        User user = this.userRepo.findByUserId(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));
        modelMapper.map(userDto, user);
        Date date = new Date();
        LocalDateTime localDateTime = date.toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();
        user.setUpdatedOn(localDateTime);
        User savedUser = this.userRepo.save(user);
        return this.modelMapper.map(savedUser, UserDto.class);
    }

    @Override
    public UserDto getUser(Map<String, Object> requestMap) {
        String userId = (String) requestMap.get("userId");
        User user = this.userRepo.findByUserId(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));
        return this.modelMapper.map(user, UserDto.class);
    }

    @Override
    public List<UserDto> getAllUsers() {
        List<User> users = this.userRepo.findAll();
        return users.stream().map(user -> modelMapper.map(user, UserDto.class)).collect(Collectors.toList());
    }

    @Override
    public void deleteUser(Map<String, Object> requestMap) {
        String userId = (String) requestMap.get("userId");
        User user = this.userRepo.findByUserId(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));
        this.userRepo.delete(user);

    }

}
