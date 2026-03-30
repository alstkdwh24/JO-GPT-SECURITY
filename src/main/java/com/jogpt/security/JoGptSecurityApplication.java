package com.jogpt.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import com.jogpt.security.config.AppProperties;

@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class JoGptSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(JoGptSecurityApplication.class, args);
    }
}
