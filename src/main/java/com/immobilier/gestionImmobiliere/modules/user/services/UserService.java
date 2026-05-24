package com.immobilier.gestionImmobiliere.modules.user.services;

import com.immobilier.gestionImmobiliere.donnees.roles.model.ERole;
import com.immobilier.gestionImmobiliere.donnees.roles.model.Role;
import com.immobilier.gestionImmobiliere.donnees.roles.repository.RoleRepository;
import com.immobilier.gestionImmobiliere.donnees.user.model.User;
import com.immobilier.gestionImmobiliere.donnees.user.repository.UserRepository;
import com.immobilier.gestionImmobiliere.modules.user.dto.requests.AuthenticateDTO;
import com.immobilier.gestionImmobiliere.modules.user.dto.requests.CreateUserDTO;
import com.immobilier.gestionImmobiliere.modules.user.dto.responses.UserInfoDTO;
import com.immobilier.gestionImmobiliere.modules.user.jwt.JwtUtils;
import com.immobilier.gestionImmobiliere.modules.user.jwtService.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class UserService {


    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    UserRepository userRepository;


    public ResponseEntity<?> authenticateUser(AuthenticateDTO authenticateDTO) {

        try {
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(authenticateDTO.getUsername(), authenticateDTO.getPassword()));


            if (authentication.isAuthenticated()) {
                UserDetailsImpl user = (UserDetailsImpl) authentication.getPrincipal();
                Map<String, Object> extraClaims = new HashMap<>();
                String jwtCookie = generateJwtCookie(user, extraClaims);
                List<String> roles = getUserRoles(user);
                return ResponseEntity.ok()
                        .header(HttpHeaders.SET_COOKIE, jwtCookie) // JWT ajouté en cookie
                        .body(UserInfoDTO.builder()
                                .username(user.getUsername())
                                .roles(roles)
                                .token(jwtCookie)
                                .build());
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Nom d'utilisateur ou mot de passe incorrect"));
            }
        }catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Nom d'utilisateur ou mot de passe incorrect"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Erreur interne du serveur"));
        }
    }

    public void createUser(CreateUserDTO createUserDTO) throws Exception {
        User user = new User();
        user.setPassword(encoder.encode(createUserDTO.getPassword()));
        Role userRole = roleRepository.findByLibelleRole(ERole.ROLE_CLIENT)
                .orElseThrow(() -> new Exception("Error: Role is not found."));
        user.setNom(createUserDTO.getNom());
        user.setPrenom(createUserDTO.getPrenom());
        user.setEmail(createUserDTO.getEmail());
        user.setDateNaissance(createUserDTO.getDateNaissance());
        user.setTelephone(createUserDTO.getTelephone());
        user.setRole(userRole);
        userRepository.save(user);

    }

    public List<String> getUserRoles(UserDetailsImpl user) {
        return user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
    }

    public String generateJwtCookie(UserDetailsImpl user, Map<String, Object> extraClaims) {
        return jwtUtils.generateAccessToken(user.getUsername(),extraClaims);
    }

    public Boolean checkIfExistsByUsername(String username) {
        System.out.println("on dans check");
        Optional<User> optionalUser = userRepository.findByEmail(username);
        return optionalUser.isPresent();
    }
}
