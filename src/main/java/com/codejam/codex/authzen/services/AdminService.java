package com.codejam.codex.authzen.services;

import com.codejam.codex.authzen.dtos.inputs.DelegateRequest;
import com.codejam.codex.authzen.dtos.inputs.RoleRequest;
import com.codejam.codex.authzen.dtos.inputs.RoleUpdateRequest;
import com.codejam.codex.authzen.dtos.outputs.AuditLogResponse;
import com.codejam.codex.authzen.dtos.outputs.UpdateUserResponse;
import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import com.codejam.codex.authzen.models.AuditLog;
import com.codejam.codex.authzen.models.Role;
import com.codejam.codex.authzen.models.User;
import com.codejam.codex.authzen.models.UserRole;
import com.codejam.codex.authzen.repositories.AuditLogRepository;
import com.codejam.codex.authzen.repositories.RoleRepository;
import com.codejam.codex.authzen.repositories.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AdminService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuditLogRepository auditLogRepository;

    public List<UserResponse> getAllUsers(String adminUsername) {
        logAction(adminUsername, "User list got successfully");

        return userRepository.findAll()
                .stream()
                .map(user -> {
                    List<String> permissionNames = userRepository.findPermissionNamesByUsername(user.getUsername());
                    return UserResponse.fromEntity(user, permissionNames); // Fixed: use actual user
                })
                .toList();
    }

    public UpdateUserResponse updateUserRoles(Long userId, RoleUpdateRequest request, String adminUsername) {
        User user = userRepository.findById(userId) // Fixed: use the provided userId
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

        List<Role> roles = roleRepository.findByNameIn(request.getRoleName()); // Assuming getRoleName returns a collection

        user.getUserRoles().clear();

        for (Role role : roles) {
            UserRole userRole = new UserRole();
            userRole.setUser(user); // Fixed: set the current user
            userRole.setRole(role); // Fixed: set the current role
            user.getUserRoles().add(userRole);
        }

        User savedUser = userRepository.save(user);
        logAction(adminUsername, "User roles updated successfully");
        return UpdateUserResponse.fromEntity(savedUser);
    }


    public List<AuditLogResponse> getAuditLogs(String adminUsername) {
        logAction(adminUsername, "Audit logs retrieved");
        
        List<AuditLog> auditLogs = auditLogRepository.findAll();

        return auditLogs.stream()
                .map(log -> {
                    return AuditLogResponse.builder()
                            .id(log.getId())
                            .username(log.getUser().getUsername())
                            .actionType(log.getActionType())
                            .ipAddress(log.getIpAddress())
                            .timestamp(log.getTimestamp())
                            .build();
                })
                .toList();
    }





    public String createRole(RoleRequest request, String adminUsername) {
        if (roleRepository.existsByName(request.getRoleName())) { // Fixed: check by request name
            throw new IllegalArgumentException("Role already exists");
        }

        Role role = new Role();
        role.setName(request.getRoleName()); // Fixed: set name from request
        role.setDescription(request.getDescription());

        roleRepository.save(role); // Fixed: save the populated role

        logAction(adminUsername, "Role created successfully");

        return "Role created successfully";
    }



    public String delegatePermissions(DelegateRequest request, String adminUsername) {
        User user = userRepository.findById(request.getUserId())
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + request.getUserId()));

        List<Role> roles = roleRepository.findByName(request.getRole());
        if (roles.isEmpty()) {
            throw new RuntimeException("Role not found: " + request.getRole());
        }
        Role role = roles.get(0);

        boolean alreadyAssigned = user.getUserRoles().stream()
                .map(userRole -> userRole.getRole().getName())
                .anyMatch(roleName -> roleName.equals(request.getRole()));
        if (alreadyAssigned) {
            return "User already has this role";
        }

        UserRole userRole = new UserRole();
        userRole.setUser(user);
        userRole.setRole(role);

        user.getUserRoles().add(userRole);
        userRepository.save(user);
        logAction(adminUsername, "Permissions delegated to " + user.getUsername());

        return "Permissions delegated successfully";
    }


    private void logAction(String adminUsername, String actionType) {
        User adminUser = userRepository.findByUsername(adminUsername)
                .orElseThrow(() -> new RuntimeException("Admin user not found"));

        AuditLog log = new AuditLog();
        log.setUser(adminUser);  // Use the retrieved admin user
        log.setActionType(actionType);
        log.setTimestamp(new Timestamp(System.currentTimeMillis()));
        log.setIpAddress("127.0.0.1");  // In a real application, capture the actual IP

        auditLogRepository.save(log);
    }


    public UserResponse getUserById(Long userId) {
        User user = userRepository.findById(userId) // Fixed: use the provided userId
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));
        List<String> permissionNames = userRepository.findPermissionNamesByUsername(user.getUsername());
        return UserResponse.fromEntity(user, permissionNames);
    }



}
