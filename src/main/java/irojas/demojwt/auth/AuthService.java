package irojas.demojwt.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import irojas.demojwt.jwt.JwtService;
import irojas.demojwt.token.Token;
import irojas.demojwt.token.TokenRepository;
import irojas.demojwt.token.TokenType;
import irojas.demojwt.user.Role;
import irojas.demojwt.user.User;
import irojas.demojwt.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(),request.getPassword()));//autenticación del usuario, si no lo encuentra lanza excepción
        User user=userRepository.findByUsername(request.getUsername()).orElseThrow(); //buscamos el user
        String jwtToken=jwtService.getToken(user); //obtenemos el token para el user
        revokeAllUserTokens(user);
        saveUserToken(user,jwtToken);
        String refreshToken=jwtService.getRefreshToken(user);
        return AuthResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
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
        User savedUser=userRepository.save(user);
       String jwtToken=jwtService.getToken(user);
       String refreshToken=jwtService.getRefreshToken(user);
        saveUserToken(savedUser, jwtToken);
        return AuthResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    private void revokeAllUserTokens(User user){
        List<Token> validUserTokens=tokenRepository.findAllValidTokensByUser(user.getId());
        if(validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(t->{
            t.setExpired(true);
            t.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }



    private void saveUserToken(User user, String jwtToken) {
        Token token=Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expired(false)
                .build();
        tokenRepository.save(token);
    }


    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader=request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String username;
        if(authHeader==null || !authHeader.startsWith("Bearer ")){
           return;
        }
        refreshToken= authHeader.substring(7);
        username=jwtService.getUsernameFromToken(refreshToken);
        if(username!=null){ //si el usuario no es nulo y no lo podemos encontrar en el SecurityContextHolder, lo vamos a buscar a la BD
            User user=this.userRepository.findByUsername(username).orElseThrow();

            if(jwtService.isTokenValid(refreshToken,user)) //si es valido, actualizo el SecurityContextHolder
            {
               String accessToken=jwtService.getToken(user);
                revokeAllUserTokens(user);
                saveUserToken(user,accessToken);
               AuthResponse authResponse=AuthResponse.builder()
                       .accessToken(accessToken)
                       .refreshToken(refreshToken)
                       .build();
               //aca podriamos hacer un return de AuthorizationResponse como en el register y login
                new ObjectMapper().writeValue(response.getOutputStream(),authResponse);
            }
        }
    }
}
