package com.example.memberssecurity.member.repository.jpa;

import com.example.entitycom.entity.member.Members;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
@Repository
public interface MemberRepository extends JpaRepository<Members, Long> {

    boolean existsByMemberId(String memberId);

    // 사용자의 전체 정보를 조회하는 메서드
    // 사용자 아이디로 조회하는 메서드
    Optional<Members> findByMemberId(String memberId);


    Optional<Members> findByMemberKey(Long currentMemberId);

    @Query("SELECT m FROM Members m JOIN FETCH m.userCredentials WHERE m.memberId = :memberId")
    Optional<Members> findByMemberIdWithCredentials(@Param("memberId") String memberId);

}
