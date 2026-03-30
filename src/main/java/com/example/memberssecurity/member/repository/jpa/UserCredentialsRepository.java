package com.example.memberssecurity.member.repository.jpa;

import com.example.entitycom.entity.member.UserCredentials;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserCredentialsRepository extends JpaRepository<UserCredentials, Long>{
}
