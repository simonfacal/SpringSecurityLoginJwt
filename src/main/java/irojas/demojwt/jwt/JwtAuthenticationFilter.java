package irojas.demojwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String token= getTokenFromRequest(request); //obtenemos token
        final String username;
        if(token==null){
            filterChain.doFilter(request,response); //si el token es nulo, le devolvemos el control a la cadena de filtros
            return;
        }
        username=jwtService.getUsernameFromToken(token);
        if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null){ //si el usuario no es nulo y no lo podemos encontrar en el SecurityContextHolder, lo vamos a buscar a la BD
            UserDetails userDetails=userDetailsService.loadUserByUsername(username);
            if(jwtService.isTokenValid(token,userDetails)) //si es valido, actualizo el SecurityContextHolder
            {
                UsernamePasswordAuthenticationToken authToken= new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);

            }
        }
        filterChain.doFilter(request,response);
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        final String authHeader=request.getHeader(HttpHeaders.AUTHORIZATION);
        if(StringUtils.hasText(authHeader)&& authHeader.startsWith("Bearer ")){
            return authHeader.substring(7);
        }
        return null;
    }
}
