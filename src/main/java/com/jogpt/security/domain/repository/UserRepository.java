package com.jogpt.security.domain.repository;

import com.jogpt.security.domain.entity.AuthProvider;
import com.jogpt.security.domain.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    Optional<User> findByAuthProviderAndProviderId(AuthProvider authProvider, String providerId);

    boolean existsByEmail(String email);
}
