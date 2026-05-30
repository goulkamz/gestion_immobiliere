package com.immobilier.gestionImmobiliere.modules.user.apis;

import com.immobilier.gestionImmobiliere.modules.user.dto.requests.ActivateUserDTO;
import com.immobilier.gestionImmobiliere.modules.user.dto.requests.AuthenticateDTO;
import com.immobilier.gestionImmobiliere.modules.user.dto.requests.CreateUserDTO;
import com.immobilier.gestionImmobiliere.modules.user.dto.requests.ResendCodeEmailDTO;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Map;

@RequestMapping("/auth")
public interface AuthentificationAPI {

        @PostMapping("/signin")
        ResponseEntity<?> authenticateUser(@Valid AuthenticateDTO authenticateDTO);

        @PostMapping("/signup")
        ResponseEntity<?> createUser(@Valid CreateUserDTO createUserDTO) throws Exception;

        @PostMapping("/activation")
        ResponseEntity<?> activateUser(@Valid ActivateUserDTO activateUserDTO);

        @PostMapping("/resend-code")
        ResponseEntity<?> resendCode(@Valid ResendCodeEmailDTO email);

}
