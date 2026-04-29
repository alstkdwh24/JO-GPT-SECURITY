package com.example.memberssecurity;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@EntityScan(basePackages = { "com.example.memberssecurity", "com.example.entitycom" })
@ComponentScan(basePackages = { "com.example.memberssecurity", "com.example.entitycom" })
public class MembersSecurityApplication {

    public static void main(String[] args) {
        new SpringApplicationBuilder(MembersSecurityApplication.class)
                .properties(
                        "spring.config.location=file:C:/courage3/JavaRealProject/potfolio_project/AI_Universal_Controller/backend/MembersSecurity/src/main/resources/application.properties")
                .run(args);
    }

}
