package com.immobilier.gestionImmobiliere.modules.user.dto.requests;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;

@Data
@Builder

public class AuthenticateDTO {

    @NotBlank(message = "L'email est obligatoire")
    @JsonAlias({"username", "userName", "email", "telephone"})
    private String email;

    @NotBlank(message = "Le mot de passe est obligatoire")
    private String password;

    @JsonIgnore
    public String getUsername(){return email;}
}