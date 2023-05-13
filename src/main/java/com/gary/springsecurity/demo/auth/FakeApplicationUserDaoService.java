package com.gary.springsecurity.demo.auth;

import com.gary.springsecurity.demo.entity.User;
import com.gary.springsecurity.demo.entity.Role;
import com.gary.springsecurity.demo.entity.Privilege;
import com.gary.springsecurity.demo.repository.UserRepository;
import com.google.common.collect.Lists;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.*;
import java.util.stream.Collectors;

import static com.gary.springsecurity.demo.security.ApplicationUserRole.*;

@Repository("fake")
@Data
@AllArgsConstructor
public class FakeApplicationUserDaoService implements ApplicationUserDao{

    @Autowired
    private final PasswordEncoder passwordEncoder;

//    @Autowired
//    private final UserRepository userRepository;

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUserName(String username) {
        return getApplicationUsers().stream()
                .filter(applicationUser -> username.equalsIgnoreCase(applicationUser.getUsername()))
                .findFirst();
    }

    private Set<SimpleGrantedAuthority> getGrantedAuthorities(Collection<Role> roles) {
        Set<SimpleGrantedAuthority> permissions = new HashSet<>();
        roles.stream().forEach((role) -> {
            Collection<Privilege> privileges = role.getPrivileges();
            permissions.addAll(privileges.stream().map((permission) -> new SimpleGrantedAuthority(permission.getName()))
                    .collect(Collectors.toSet()));
            permissions.add(new SimpleGrantedAuthority(role.getName()));
        });

        return permissions;
    }

    private List<ApplicationUser> getApplicationUsers() {
        /**
         * Retrieve user information from DB
         */
//        List<ApplicationUser> applicationUsers = new ArrayList<>();
//        List<User> users = userRepository.findAll();
//        users.stream().forEach((user) ->{
//
//            Collection<Role> roles = user.getRoles();
//            Set<SimpleGrantedAuthority> grantedAuthorities = getGrantedAuthorities(roles);
//            ApplicationUser appUser = new ApplicationUser(
//                    passwordEncoder.encode(user.getPassword()),
//                    user.getEmail(), grantedAuthorities, true,
//                    true, true, true
//            );
//            applicationUsers.add(appUser);
//        });
        /**
         * The followings are hard-coded to obtain all the users on the fly.
         */
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        passwordEncoder.encode("password"), "user", STUDENT.getGrantedAuthority(),
                        true,true, true, true
                ),
                new ApplicationUser(
                        passwordEncoder.encode("123456"), "admin", ADMIN.getGrantedAuthority(),
                        true,true, true, true
                ),
                new ApplicationUser(
                        passwordEncoder.encode("123456"), "loyalty", LOYALTY.getGrantedAuthority(),
                        true,true, true, true
                )
        );

        return applicationUsers;
    }
}
