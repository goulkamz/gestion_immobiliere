package com.immobilier.gestionImmobiliere.modules.user.controllers;

import com.immobilier.gestionImmobiliere.modules.user.apis.AuthentificationAPI;
import com.immobilier.gestionImmobiliere.modules.user.dto.requests.ActivateUserDTO;
import com.immobilier.gestionImmobiliere.modules.user.dto.requests.AuthenticateDTO;
import com.immobilier.gestionImmobiliere.modules.user.dto.requests.CreateUserDTO;
import com.immobilier.gestionImmobiliere.modules.user.dto.requests.ResendCodeEmailDTO;
import com.immobilier.gestionImmobiliere.modules.user.services.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

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
    public ResponseEntity<?> createUser(@Valid @RequestBody CreateUserDTO createUserDTO) throws Exception {
           return userService.createUser(createUserDTO);
    }

    @Override
    public ResponseEntity<?> activateUser(@Valid @RequestBody ActivateUserDTO activationCode) {
        return userService.activation(activationCode);
    }

    @Override
    public ResponseEntity<?> resendCode(@Valid @RequestBody ResendCodeEmailDTO email) {
       return userService.resendCode(email);
    }
}
