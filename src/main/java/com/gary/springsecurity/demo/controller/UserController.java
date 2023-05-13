//package com.gary.springsecurity.demo.controller;
//
//import com.gary.springsecurity.demo.entity.Privilege;
//import com.gary.springsecurity.demo.entity.Role;
//import com.gary.springsecurity.demo.entity.User;
//import com.gary.springsecurity.demo.repository.UserRepository;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.access.annotation.Secured;
//import org.springframework.security.access.prepost.PreAuthorize;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.web.bind.annotation.*;
//
//import java.security.Principal;
//import java.util.*;
//import java.util.stream.Collectors;
//
//@RestController
//@RequestMapping("/user")
//public class UserController {
//
//    @Autowired
//    private UserRepository repository;
//
//    @Autowired
//    private BCryptPasswordEncoder passwordEncoder;
//
//    @PostMapping("/adminregister")
//    public String registerAdmin(@RequestBody User user) {
//        //default role
//        Role role = new Role("ROLE_ADMIN");
//        //default privilege
//        Privilege privilege1 = new Privilege("READ_PREVILEGE");
//        Privilege privilege2 = new Privilege("WRITE_PREVILEGE");
//        role.setPrivileges(Arrays.asList(privilege1, privilege2));
//        user.setRoles(Arrays.asList(role));
//        String encryptedPwd = passwordEncoder.encode(user.getPassword());
//        user.setPassword(encryptedPwd);
//        user.setActive(true);
//        user.setTokenExpired(false);
//
//        repository.save(user);
//        return "Hi " + user.getEmail() + " welcome to group !";
//    }
//
//    @PostMapping("/register")
//    public String register(@RequestBody User user) {
//        //default role
//        Role role = new Role("ROLE_USER");
//        //default privilege
//        Privilege privilege = new Privilege("READ_PREVILEGE");
//        role.setPrivileges(Arrays.asList(privilege));
//        user.setRoles(Arrays.asList(role));
//        String encryptedPwd = passwordEncoder.encode(user.getPassword());
//        user.setPassword(encryptedPwd);
//        repository.save(user);
//        return "Hi " + user.getEmail() + " welcome to group !";
//    }
//    //If loggedin user is ADMIN -> ADMIN OR MODERATOR
//    //If loggedin user is MODERATOR -> MODERATOR
//
//    @GetMapping("/access/{userId}/{userRole}")
//    //@Secured("ROLE_ADMIN")
//    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
//    public String giveAccessToUser(@PathVariable int userId, @PathVariable String userRole, Principal principal) {
//        User user = repository.findById(userId).get();
//        List<String> activeRoles = getRolesByLoggedInUser(principal);
//        List<Role> newRole = new ArrayList<>();
//        if (activeRoles.contains(userRole)) {
//            //newRole = user.getRoles();
//            //newRole.add(userRole);
//            user.setRoles(newRole);
//        }
//        repository.save(user);
//        return "Hi " + user.getEmail() + " New Role assign to you by " + principal.getName();
//    }
//
//    @GetMapping
//    //@Secured("ROLE_ADMIN")
//    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
//    public List<User> loadUsers() {
//        return repository.findAll();
//    }
//
//    @GetMapping("/test")
//    @PreAuthorize("hasAnyRole('ROLE_USER','ROLE_ADMIN')")
//    public String testUserAccess() {
//        return "user can only access this !";
//    }
//
//    private List<String> getRolesByLoggedInUser(Principal principal) {
//        Collection<Role> roles = getLoggedInUser(principal).getRoles();
//        Set<String> assignRoles = new HashSet<>();
//        for(Role role: roles) {
//            assignRoles.add(role.getName());
//            if(role.getName().equalsIgnoreCase("ROLE_ADMIN")) {
//                assignRoles.add("ROLE_LOYALTY");
//                assignRoles.add("ROLE_USER");
//            } else if(role.getName().equalsIgnoreCase("ROLE_LOYALTY")) {
//                assignRoles.add("ROLE_USER");
//            }
//        }
//        return assignRoles.stream().collect(Collectors.toList());
//    }
//
//    private User getLoggedInUser(Principal principal) {
//        return repository.findByEmail(principal.getName()).get();
//    }
//}
