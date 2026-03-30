package com.jogpt.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/**
 * JPA Auditing 활성화 설정 (@CreatedDate, @LastModifiedDate)
 */
@Configuration
@EnableJpaAuditing
public class JpaConfig {
}
