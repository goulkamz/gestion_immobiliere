package com.immobilier.gestionImmobiliere.modules.user.dto.responses;

import lombok.Builder;
import lombok.Data;

import java.util.List;


    @Data
    @Builder
    public class UserInfoDTO {

        private String username;
        private String token;
        private List<String> roles;


}
