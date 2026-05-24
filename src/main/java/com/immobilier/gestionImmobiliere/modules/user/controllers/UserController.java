package com.immobilier.gestionImmobiliere.modules.user.controllers;

import com.immobilier.gestionImmobiliere.modules.user.apis.AuthentificationAPI;
import com.immobilier.gestionImmobiliere.modules.user.dto.requests.AuthenticateDTO;
import com.immobilier.gestionImmobiliere.modules.user.dto.requests.CreateUserDTO;
import com.immobilier.gestionImmobiliere.modules.user.dto.responses.UserInfoDTO;
import com.immobilier.gestionImmobiliere.modules.user.jwtService.UserDetailsImpl;
import com.immobilier.gestionImmobiliere.modules.user.services.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class UserController implements AuthentificationAPI {

    @Autowired
    UserService userService;

    @Override
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody AuthenticateDTO authenticateDTO) {
        return userService.authenticateUser(authenticateDTO);
    }


    @Override
    public ResponseEntity<?> createUser(@Valid @RequestBody CreateUserDTO createUserDTO) {
        Map<String, Object> response = new HashMap<>();
        try {
            if(userService.checkIfExistsByUsername((createUserDTO.getEmail())))
                return ResponseEntity.badRequest().body("Nom d'utilisateur déjà utilisé");

            userService.createUser(createUserDTO);

            response.put("success", true);
            response.put("message", "Utilisateur enregistré");
            return ResponseEntity.ok(response);
        } catch(Exception ex) {
            return ResponseEntity.badRequest().body(ex.getMessage());
        }
    }
}
