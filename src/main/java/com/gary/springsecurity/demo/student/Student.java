package com.gary.springsecurity.demo.student;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.ToString;

@Data
@AllArgsConstructor
@ToString
public class Student {
    private final Integer studentId;
    private final String studentName;
}
