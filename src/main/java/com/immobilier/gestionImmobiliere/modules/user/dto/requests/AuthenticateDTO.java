package com.immobilier.gestionImmobiliere.modules.user.dto.requests;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;

@Data
@Builder

public class AuthenticateDTO {

    @NotBlank(message = "L'email est obligatoire")
    private String email;  // ← utiliser "email" au lieu de "username"

    @NotBlank(message = "Le mot de passe est obligatoire")
    private String password;

    public String getUsername(){return email;}
}