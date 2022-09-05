package ru.msaggik.spring.SpringBootSecurityJWT.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import ru.msaggik.spring.SpringBootSecurityJWT.models.Person;
import ru.msaggik.spring.SpringBootSecurityJWT.services.PersonDetailsService;

@Component
public class PersonValidator implements Validator {
    // внедрение PersonDetailService для проверки существования в БД регистрирующего пользователя
    private final PersonDetailsService personDetailsService;
    @Autowired
    public PersonValidator(PersonDetailsService personDetailsService) {
        this.personDetailsService = personDetailsService;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        // обозначение валидатора для объекта класса Person
        return Person.class.equals(aClass);
    }

    @Override
    public void validate(Object target, Errors errors) {
        Person person = (Person) target;
        // использование PersonDetailService для проверки существования в БД регистрирующего пользователя
        // методом просмотра выброски исключения
        try {
            personDetailsService.loadUserByUsername(person.getUsername());
        } catch (UsernameNotFoundException ignored) { // игнорирование исключения
            return; // то, что нужно (пользователь с таким именем не найден)
        }
        // иначе будет выброшена ошибка
        errors.rejectValue("username", "", "Человек с таким именем уже существует");
    }
}
