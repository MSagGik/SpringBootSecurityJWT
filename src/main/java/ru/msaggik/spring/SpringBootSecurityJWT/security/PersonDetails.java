package ru.msaggik.spring.SpringBootSecurityJWT.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import ru.msaggik.spring.SpringBootSecurityJWT.models.Person;

import java.util.Collection;
import java.util.Collections;

public class PersonDetails implements UserDetails {
    private final Person person;

    public PersonDetails(Person person) {
        this.person = person;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // определение роли при авторизации
        // (при выборе способа ограничивания доступа "действия",
        // нужно было-бы создавать список данных действий)
        return Collections.singletonList(new SimpleGrantedAuthority(person.getRole()));
    }

    @Override
    public String getPassword() {
        return this.person.getPassword();
    }

    @Override
    public String getUsername() {
        return this.person.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // действительность аккаунта
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // не заблокирован
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // пароль не просрочен
    }

    @Override
    public boolean isEnabled() {
        return true; // включение аккаунта
    }

    // метод доступа к аутентифицированному пользователю для получения имеющихся полей
    public Person getPerson() {
        return this.person;
    }
}
