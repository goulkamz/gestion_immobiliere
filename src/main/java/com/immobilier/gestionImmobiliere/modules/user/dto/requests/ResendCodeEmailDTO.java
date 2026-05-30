package com.immobilier.gestionImmobiliere.modules.user.dto.requests;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor

public class ResendCodeEmailDTO {

        @NotBlank(message = "L'email est obligatoire")
        @JsonAlias({"email"})
        private String email;

}
