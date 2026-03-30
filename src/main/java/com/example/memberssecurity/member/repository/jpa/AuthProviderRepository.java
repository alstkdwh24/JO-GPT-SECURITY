package com.example.memberssecurity.member.repository.jpa;

import com.example.entitycom.entity.member.AuthProviders;
import com.example.entitycom.entity.member.Members;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthProviderRepository extends JpaRepository<AuthProviders, Long> {
    Optional<Members> findByProviderAndProviderId(String provider, String providerId);
}
