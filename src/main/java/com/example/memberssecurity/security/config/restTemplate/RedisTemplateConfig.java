package com.example.memberssecurity.security.config.restTemplate;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
// 이 클래스가 스프링 설정 클래스임을 나타냅니다.
// 빈 등록 등 설정 관련 코드를 작성할 때 사용합니다.
public class RedisTemplateConfig {

    @Bean("redisTemplate")
    public RedisTemplate<String, String> redisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, String> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);
        redisTemplate.setKeySerializer(new StringRedisSerializer());
        redisTemplate.setValueSerializer(new StringRedisSerializer());
        return redisTemplate;
    }

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    // redisTemplate.opsForValue()를 반환합니다.
    // 이 메서드를 통해 Redis의 String 타입 데이터를 쉽게 다룰수 있습니다.
    // opsForValue().set(key, value, timeout, unit) 등으로 값 저장 / 조회 가능
    public ValueOperations<String, String> opsForValue() {
        return redisTemplate.opsForValue();
    }

    public void delete(String string) {
        redisTemplate.delete(string);
    }
}
