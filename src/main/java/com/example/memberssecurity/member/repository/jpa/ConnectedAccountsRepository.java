package com.example.memberssecurity.member.repository.jpa;

import com.example.entitycom.entity.connect.ConnectedAccounts;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ConnectedAccountsRepository extends JpaRepository<ConnectedAccounts, Long> {

    // memberKey + provider로 이미 연결된 계정 찾기
    Optional<ConnectedAccounts> findByMember_MemberKeyAndProvider(Long memberKey, String provider);

    // 유저의 연결된 계정 목록
    List<ConnectedAccounts> findAllByMember_MemberKey(Long memberKey);
}
