package ru.msaggik.spring.SpringBootSecurityJWT.config;

import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.msaggik.spring.SpringBootSecurityJWT.security.JWTUtil;
import ru.msaggik.spring.SpringBootSecurityJWT.services.PersonDetailsService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// класс для отлавливания всех запросов для дальнейших действий
@Component
public class JWTFillter extends OncePerRequestFilter {

    // внедрение объекта проверки токена
    private final JWTUtil jwtUtil;

    // внедрение PersonDetailsService для аутентификации
    private final PersonDetailsService personDetailsService;

    @Autowired
    public JWTFillter(JWTUtil jwtUtil, PersonDetailsService personDetailsService) {
        this.jwtUtil = jwtUtil;
        this.personDetailsService = personDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // извлечённый заголовок передачи JWT токена
        String authHeader = request.getHeader("Authorization");

        // если ( заголовок не пустой И в нём есть какая-либо строка И если он начинается со слова "Bearer ")
        if (authHeader != null && !authHeader.isBlank() && authHeader.startsWith("Bearer ")) {
            // то нужно данный токен получить и посмотреть его подлинность
            String jwt = authHeader.substring(7); // просмотр заголовка с 7 индекса
            // если токен пустой
            if (jwt.isBlank()) {
                // то выдаётся ошибка
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, // статус 400
                        "Invalid JWT Token in Bearer Header");
            } else { // иначе токен проверяется
                try {
                    String username = jwtUtil.validateTokenAndRetrieveClaim(jwt);

                    // проведение аутентификации пользователя
                    UserDetails userDetails = personDetailsService.loadUserByUsername(username);
                    // проведение авторизации пользователя
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(userDetails,
                                    userDetails.getPassword(),
                                    userDetails.getAuthorities());
                    // если у пользователя нет контекста, то он создаётся
                    if (SecurityContextHolder.getContext().getAuthentication() == null) {
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    }
                } catch (JWTVerificationException exc) {
                    // если что-то не так с токеном, то выдаётся исключение
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST, // статус 400
                            "Invalid JWT Token");
                }
            }
        }
        // дальнейшее продвижение запроса по следующим фильтрам
        filterChain.doFilter(request, response);
    }
}
