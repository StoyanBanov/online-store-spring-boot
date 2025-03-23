package app.security.service;

import app.exception.DomainException;
import app.security.AuthenticationMetadata;
import app.user.model.User;
import app.user.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AuthDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    public AuthDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new DomainException("User with this email does not exist!"));

        return new AuthenticationMetadata(user.getId(), email, user.getPassword(), user.getRole());
    }
}
