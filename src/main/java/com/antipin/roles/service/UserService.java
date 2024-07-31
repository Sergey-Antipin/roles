package com.antipin.roles.service;

import com.antipin.roles.exception.SignInMaxAttemptsException;
import com.antipin.roles.exception.UserNotFoundException;
import com.antipin.roles.model.User;
import com.antipin.roles.model.UserPrincipal;
import com.antipin.roles.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepository repository;

    private final LoginAttemptService loginAttemptService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (loginAttemptService.isBlocked()) {
            throw new SignInMaxAttemptsException();
        }
        User user = repository
                .findUserByUsername(username)
                .orElseThrow(() -> new UserNotFoundException(username));
        return new UserPrincipal(user);
    }

    public User getById(Long id) {
        return repository.findById(id)
                .orElseThrow(() -> new UserNotFoundException(id));
    }

    public User getByUsername(String username) {
        return repository.findUserByUsername(username)
                .orElseThrow(() -> new UserNotFoundException(username));
    }

    public List<User> getAll() {
        return repository.findAll();
    }

    public User createNewUser(User user) {
        return repository.save(user);
    }


}
