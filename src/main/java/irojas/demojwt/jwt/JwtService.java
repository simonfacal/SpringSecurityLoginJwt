package irojas.demojwt.jwt;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;


@Service
public class JwtService {
    @Value("${spring.security.jwt.secret-key}")
    private String secretKey; //la key que queramos que sea de 256 bits
    @Value("${spring.security.jwt.expiration}")
    private Long jwtExpiration;

    @Value("${spring.security.refresh-token.expiration}")
    private Long refreshExpiration;

    public String getToken(UserDetails user) {
        return getToken(new HashMap<>(),user);
    }

    private String getToken(HashMap<String,Object> extraClaims, UserDetails user) {

      return Jwts.builder()
              .setClaims(extraClaims)
              .setSubject(user.getUsername())
              .setIssuedAt(new Date(System.currentTimeMillis()))
              .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
              .signWith(getKey()) //elige el algoritmo de firma más seguro segun el tamaño de bytes de la key
              .compact();
    }

    private Key getKey(){
        byte[]keyBytes= Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String getUsernameFromToken(String token) {
        return getClaim(token,Claims::getSubject); //en el subject del claim tenemos el username
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username=getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername())&& !isTokenExpired(token));
    }

    private Claims getAllClaims(String token){
       return Jwts
               .parserBuilder()
               .setSigningKey(getKey())
               .build()
               .parseClaimsJws(token)
               .getBody();

    }

    public <T> T getClaim(String token, Function<Claims,T>claimsResolver){
        final Claims claims=getAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Date getExpiration(String token)
    {
        return getClaim(token,Claims::getExpiration);
    }

    private Boolean isTokenExpired(String token){
        return getExpiration(token).before(new Date());
    }


}
