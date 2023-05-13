package com.gary.springsecurity.demo.auth;

import java.util.Optional;

public interface ApplicationUserDao {
    public Optional<ApplicationUser> selectApplicationUserByUserName(String username);
}
