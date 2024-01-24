package irojas.demojwt.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    @Override
    public void changePassword(ChangePasswordRequest request, Principal connectedUser) {
        var user=(User) ((UsernamePasswordAuthenticationToken)connectedUser).getPrincipal();
        //check if the current password is correct
        if(!passwordEncoder.matches(request.getCurrentPassword(),user.getPassword())) {
            throw new IllegalStateException("Wrong password"); //Cambiar esta excepcion por alguna más "correcta"
        }
        if(!request.getNewPassword().equals(request.getConfirmationPassword())){
            throw new IllegalStateException("Password's are not the same"); //Cambiar esta excepcion por alguna más "correcta"
        }
        //update the passwoord
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        //save the new password
        userRepository.save(user);
    }
}
