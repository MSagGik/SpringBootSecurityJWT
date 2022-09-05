package ru.msaggik.spring.SpringBootSecurityJWT.controllers;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import ru.msaggik.spring.SpringBootSecurityJWT.dto.AuthenticationDTO;
import ru.msaggik.spring.SpringBootSecurityJWT.dto.PersonDTO;
import ru.msaggik.spring.SpringBootSecurityJWT.models.Person;
import ru.msaggik.spring.SpringBootSecurityJWT.security.JWTUtil;
import ru.msaggik.spring.SpringBootSecurityJWT.services.RegistrationService;
import ru.msaggik.spring.SpringBootSecurityJWT.util.PersonValidator;

import javax.validation.Valid;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {
    // внедрение валидатора
    private final PersonValidator personValidator;

    // внедрение сервиса регистрации
    private final RegistrationService registrationService;

    // внедрение класса работы с токенами
    private final JWTUtil jwtUtil;

    // внедрение маппера для работы с DTO
    private final ModelMapper modelMapper;

    // внедрение бина для проверки логина и пароля
    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthController(PersonValidator personValidator, RegistrationService registrationService, JWTUtil jwtUtil, ModelMapper modelMapper, AuthenticationManager authenticationManager) {
        this.personValidator = personValidator;
        this.registrationService = registrationService;
        this.jwtUtil = jwtUtil;
        this.modelMapper = modelMapper;
        this.authenticationManager = authenticationManager;
    }

    // метод представления для аутентификации
    @GetMapping("/login")
    public String loginPage() {
        return "auth/login";
    }

    // страница регистрации нового пользователя
    // (аннотация @ModelAttribute("person") в модель Person положит пустого пользователя)
    @GetMapping("/registration")
    public String registrationPage(@ModelAttribute("person") Person person) {
        return "/auth/registration";
    }

    // метод приёма данных с формы регистрации
    @PostMapping("/registration")
    public Map<String, String> performRegistration(@RequestBody @Valid PersonDTO personDTO,
                                      BindingResult bindingResult) {
        // получение от клиента данных пользователя
        Person person = convertToPerson(personDTO);

        // проверка пользователя на исключение повторной регистрации
        // в bindingResult будет помещаться возможная ошибка
        personValidator.validate(person, bindingResult);

        if (bindingResult.hasErrors()) {
            // демонстрация пользователю ошибки
            return Map.of("message", "Ошибка!");
        }

        // вызов метода регистрации пользователя
        registrationService.register(person);

        String token = jwtUtil.generateToken(person.getUsername());
        // демонстрация пользователю успешности отправки данных
        return Map.of("jwt-token", token);
    }

    // метод конвертирования PersonDTO в Person
    public Person convertToPerson(PersonDTO personDTO) {
        return this.modelMapper.map(personDTO, Person.class);
    }

    // метод принятия логина и пароля с последующей выдачей нового JWT токена с новым сроком годности
    @PostMapping("/login")
    public Map<String, String> performLogin(@RequestBody AuthenticationDTO authenticationDTO) {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(authenticationDTO.getUsername(),
                        authenticationDTO.getPassword());
        // проверка логина и пароля
        try {
            authenticationManager.authenticate(authenticationToken);
        } catch (BadCredentialsException e) {
            // исключение на случай неправильного логина и пароля
            return Map.of("message", "Incorrect credentials!");
        }
        // метод генерации нового токена
        String token = jwtUtil.generateToken(authenticationDTO.getUsername());
        return Map.of("jwt-token", token);
    }
}
