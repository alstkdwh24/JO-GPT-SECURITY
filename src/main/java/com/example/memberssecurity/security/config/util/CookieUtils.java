package com.example.memberssecurity.security.config.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.util.SerializationUtils;

import java.util.Base64;
import java.util.Optional;

public class CookieUtils {
    // 이름으로 쿠키 가져오기
    public static Optional<Cookie> getCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null && cookies.length > 0) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    return Optional.of(cookie);
                }
            }
        }
        return Optional.empty();
    }

    // 새로운 쿠키 추가
    public static void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie1 = new Cookie(name, value);
        cookie1.setPath("/");
        cookie1.setHttpOnly(true);
        cookie1.setMaxAge(maxAge);
        response.addCookie(cookie1);
    }

    // 쿠키 삭제
    public static void deleteCookie(HttpServletRequest request,HttpServletResponse response, String name) {
        Cookie[] cookies = request.getCookies();
        if( cookies != null && cookies.length > 0 ) {
            for( Cookie cookie : cookies ) {
                if( cookie.getName().equals(name) ) {
                    cookie.setMaxAge(0);
                    cookie.setPath("/");
                    cookie.setValue("");
                    response.addCookie(cookie);
                }
            }
        }
    }

    public static String serialize(Object object) {
        return Base64.getUrlEncoder().encodeToString(SerializationUtils.serialize(object));
    }

    public static <T> T deserialize(Cookie cookie, Class<T> clazz) {
        return clazz.cast(SerializationUtils.deserialize(Base64.getUrlDecoder().decode(cookie.getValue())));
    }
}
