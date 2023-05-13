package com.gary.springsecurity.demo.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Collection;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Entity
@Table(name = "ROLES")
public class Role implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Integer id;

    private String name;

    @ManyToMany(mappedBy="roles")
    private Collection<User> users;

    @ManyToMany(cascade = {CascadeType.ALL}, fetch = FetchType.EAGER)
    @JoinTable(
            name="role_privileges",
            joinColumns = @JoinColumn(
                    name="role_id", referencedColumnName = "id"
            ),
            inverseJoinColumns = @JoinColumn(
                    name="privilege_id", referencedColumnName = "id"
            )
    )
    private Collection<Privilege> privileges;

    public Role(String name) {
        this.name = name;
    }
}
