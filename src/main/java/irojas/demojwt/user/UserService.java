package irojas.demojwt.user;

import java.security.Principal;

public interface UserService {

    public void changePassword(ChangePasswordRequest request, Principal connectedUser);
}
