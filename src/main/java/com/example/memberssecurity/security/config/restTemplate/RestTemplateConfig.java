package com.example.memberssecurity.security.config.restTemplate;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration("memberSecurityRestTemplateConfig")
public class RestTemplateConfig {
    @Bean
    public RestTemplate memberSecurityRestTemplate() {
        return new RestTemplate();
    }

}
