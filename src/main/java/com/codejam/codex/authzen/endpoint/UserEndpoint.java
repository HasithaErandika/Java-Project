package com.codejam.codex.authzen.endpoint;

import com.codejam.codex.authzen.dtos.inputs.UpdateUserRequest;
import com.codejam.codex.authzen.dtos.outputs.UpdateUserResponse;
import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import com.codejam.codex.authzen.models.User;
import com.codejam.codex.authzen.services.UserService;
import com.codejam.codex.authzen.utils.ValidationUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Endpoint responsible for user-related operations such as fetching and updating profiles.
 */
@Component
public class UserEndpoint {

    private final UserService userService;
    private final ValidationUtil validationUtil;

    @Autowired
    public UserEndpoint(UserService userService, ValidationUtil validationUtil) {
        this.userService = userService;
        this.validationUtil = validationUtil;
    }

    /**
     * Fetches the profile of the user by username.
     *
     * @param username Username of the user
     * @return UserResponse DTO containing profile data
     */
    public UserResponse getProfile(String username) {
        if (!StringUtils.hasText(username)) {
            throw new IllegalArgumentException("Username cannot be empty");
        }
        validationUtil.validateUsername(username);
        return userService.getProfile(username);
    }

    /**
     * Updates the user profile based on the given request.
     *
     * @param username       Username of the user
     * @param updateRequest  Data to update
     */
    public UpdateUserResponse updateUser(String username, UpdateUserRequest updateRequest) {
        if (!StringUtils.hasText(username)) {
            throw new IllegalArgumentException("Username cannot be empty");
        }
        if (updateRequest == null) {
            throw new IllegalArgumentException("Update request cannot be null");
        }
        validationUtil.validateUsername(username);
        validationUtil.validateUpdateUserRequest(updateRequest);
        return userService.updateUser(username, updateRequest);
    }
}