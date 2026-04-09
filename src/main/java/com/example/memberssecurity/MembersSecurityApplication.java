package com.example.memberssecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@EntityScan(basePackages = {"com.example.memberssecurity", "com.example.entitycom"})
@ComponentScan(basePackages = {"com.example.memberssecurity", "com.example.entitycom"})
public class MembersSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(MembersSecurityApplication.class, args);
    }

}
