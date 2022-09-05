package ru.msaggik.spring.SpringBootSecurityJWT.controllers;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import ru.msaggik.spring.SpringBootSecurityJWT.security.PersonDetails;

@Controller
public class HelloController {
    @GetMapping("/hello")
    public String sayHello() {
        return "hello";
    }

    // реализация метода для доступа в java потоку
    @GetMapping("/showUserInfo")
    @ResponseBody
    public String showUserInfo() {
        // получение доступа к объекту authentication
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // получение доступа к personDetails (принципалу)
        PersonDetails personDetails = (PersonDetails)authentication.getPrincipal();
        System.out.println(personDetails.getPerson()); // вывод на экран полей пользователя

        // возвращение имени пользователя
        return personDetails.getUsername();
    }

    @GetMapping("/admin") // страница для админа
    public String adminPage() {
        return "admin";
    }
}
