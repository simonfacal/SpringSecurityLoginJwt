package irojas.demojwt.token;

import irojas.demojwt.user.User;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Token {
    @Id
    @GeneratedValue
    private Integer id;
    private String token;
    private TokenType tokenType;
    private boolean expired;
    private boolean revoked; //si queres revocar manualmente, o si queres que, cuando se resetea el server, revocar todos los tokens
    @ManyToOne
    @JoinColumn(name="user_id")
    private User user;

}
