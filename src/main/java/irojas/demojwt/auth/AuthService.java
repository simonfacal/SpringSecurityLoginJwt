package irojas.demojwt.auth;

import irojas.demojwt.jwt.JwtService;
import irojas.demojwt.user.Role;
import irojas.demojwt.user.User;
import irojas.demojwt.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(),request.getPassword()));//autenticación del usuario, si no lo encuentra lanza excepción
        UserDetails user=userRepository.findByUsername(request.getUsername()).orElseThrow(); //buscamos el user
        String jwtToken=jwtService.getToken(user); //obtenemos el token para el user
        return AuthResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthResponse register(RegisterRequest request) {
        User user= User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .country(request.getCountry())
                .role(Role.USER)
                .build();
        userRepository.save(user);
       String jwtToken=jwtService.getToken(user);
        return AuthResponse.builder()
                .token(jwtToken)
                .build();
    }


}
