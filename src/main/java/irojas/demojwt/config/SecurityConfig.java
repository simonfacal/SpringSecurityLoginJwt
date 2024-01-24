package irojas.demojwt.config;

import irojas.demojwt.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authProvider;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf->csrf.disable()) //deshabitar csrf
                .authorizeHttpRequests(authRequest->
                        authRequest
                                .requestMatchers("/auth/**").permitAll() //permite que se pueda acceder sin autorización a todos los endpoints que esten en la ruta /auth
                                .anyRequest().authenticated()  //cualquier otro endpoint le pedis que se autentique
                 )
                .sessionManagement(sessionManager-> //desactivamos las sesiones
                        sessionManager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authProvider)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class) //añadimos filtro de JWT
                .build();
    }


}
