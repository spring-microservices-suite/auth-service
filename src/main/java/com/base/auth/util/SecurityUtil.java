package com.base.auth.util;

import com.base.auth.exception.ResourceNotFoundException;
import com.base.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class SecurityUtil {

    @Autowired
    UserRepository userRepository;

    public boolean isSelfOrAdmin(String targetUserId) {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        String emailId = auth.getName();
        boolean isAdmin = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

        var currentUser = userRepository.findByEmailId(emailId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "emailId", emailId));

        return isAdmin || currentUser.getUserId().equals(targetUserId);
    }

}
