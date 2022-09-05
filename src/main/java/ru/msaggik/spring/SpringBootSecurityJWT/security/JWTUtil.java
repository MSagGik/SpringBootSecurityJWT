package ru.msaggik.spring.SpringBootSecurityJWT.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.ZonedDateTime;
import java.util.Date;

// класс для работы с JWT токенами
@Component
public class JWTUtil {

    // секретный ключ (находится в application.properties)
    @Value("${jwt_secret}")
    private String secret;

    // метод генерации токена
    // в токен помещаются данные пользователя (имя)
    public String generateToken(String username) {
        // срок годности токена (60 минут)
        Date expirationDate = Date.from(ZonedDateTime.now().plusMinutes(60).toInstant());
        // создание JWT токена
        return JWT.create()
                .withSubject("User details") // поле токена (данные пользователя)
                .withClaim("username", username) // первая пара ключ-значение, помещаются в тело токена
                .withClaim("username123", username) // вторая пара ключ-значение, помещаются в тело токена
                .withIssuedAt(new Date()) // время выдачи токена
                .withIssuer("admin") // кто выдал токен
                .withExpiresAt(expirationDate) // срок годности токена
                .sign(Algorithm.HMAC256(secret)); // подпись токена (алгоритм шифрования("секретный ключ"))
    }

    // метод приёма запроса с токеном и извлечения из него данных пользователя
    public String validateTokenAndRetrieveClaim(String token) throws JWTVerificationException {
        // валидация токена, проверка на подлинность
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secret))
                .withSubject("User details") // поле токена (данные пользователя)
                .withIssuer("admin") // кем выдан токен
                .build();
        // проверка и декодирование токена
        DecodedJWT jwt = verifier.verify(token);

        // получение данных из декодированного токена
        return jwt.getClaim("username").asString();
    }
}
