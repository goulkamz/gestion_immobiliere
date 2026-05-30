package com.immobilier.gestionImmobiliere.modules.user.services;

import com.immobilier.gestionImmobiliere.donnees.roles.model.ERole;
import com.immobilier.gestionImmobiliere.donnees.roles.model.Role;
import com.immobilier.gestionImmobiliere.donnees.roles.repository.RoleRepository;
import com.immobilier.gestionImmobiliere.donnees.user.model.PendingRegistration;
import com.immobilier.gestionImmobiliere.donnees.user.model.User;
import com.immobilier.gestionImmobiliere.donnees.user.model.Validation;
import com.immobilier.gestionImmobiliere.donnees.user.repository.PendingRegistrationRepository;
import com.immobilier.gestionImmobiliere.donnees.user.repository.UserRepository;
import com.immobilier.gestionImmobiliere.exceptions.EmailAlreadyExistsException;
import com.immobilier.gestionImmobiliere.exceptions.InvalidEmailException;
import com.immobilier.gestionImmobiliere.exceptions.InvalidPasswordException;
import com.immobilier.gestionImmobiliere.exceptions.RoleNotFoundException;
import com.immobilier.gestionImmobiliere.modules.user.dto.requests.ActivateUserDTO;
import com.immobilier.gestionImmobiliere.modules.user.dto.requests.AuthenticateDTO;
import com.immobilier.gestionImmobiliere.modules.user.dto.requests.CreateUserDTO;
import com.immobilier.gestionImmobiliere.modules.user.dto.requests.ResendCodeEmailDTO;
import com.immobilier.gestionImmobiliere.modules.user.dto.responses.UserInfoDTO;
import com.immobilier.gestionImmobiliere.modules.user.jwt.JwtUtils;
import com.immobilier.gestionImmobiliere.modules.user.jwtService.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import static java.time.temporal.ChronoUnit.MINUTES;

import java.time.Instant;
import java.util.*;

@Service
public class UserService {

    private static final int CODE_EXPIRATION_MINUTES = 10;
    private static final int MAX_RESEND_ATTEMPTS = 3;

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

    @Autowired
    PendingRegistrationRepository pendingRegistrationRepository;

    @Autowired
    ValidationService validationService;

    @Autowired
    NotificationService notificationService;


    public ResponseEntity<?> authenticateUser(AuthenticateDTO authenticateDTO) {

            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(authenticateDTO.getUsername(), authenticateDTO.getPassword()));

                UserDetailsImpl user = (UserDetailsImpl) authentication.getPrincipal();
                Map<String, Object> extraClaims = new HashMap<>();
                String jwtCookie = generateJwtCookie(user, extraClaims);
                List<String> roles = getUserRoles(user);

            UserInfoDTO userInfo = UserInfoDTO.builder()
                .username(user.getUsername())
                .roles(roles)
                .token(jwtCookie)
                .build();

            return buildSuccessResponse(HttpStatus.OK, "Authentification réussie", "LOGIN_SUCCESS", userInfo);
    }

    @Transactional
    public ResponseEntity<?> createUser(CreateUserDTO createUserDTO) throws Exception {
        if(!createUserDTO.getEmail().contains(".") || !createUserDTO.getEmail().contains("@")){
            throw new InvalidEmailException(createUserDTO.getEmail());
        }

        if(checkIfExistsByUsername(createUserDTO.getEmail())){
            throw new EmailAlreadyExistsException(createUserDTO.getEmail());
        }

        if (createUserDTO.getTelephone() != null && userRepository.existsByTelephone(createUserDTO.getTelephone())) {
            throw new RuntimeException("Ce numéro de téléphone est déjà utilisé");
        }

        if (createUserDTO.getPassword() == null || createUserDTO.getPassword().isEmpty()) {
            throw new InvalidPasswordException("Le mot de passe est invalide ou nul.");
        }

        // Rechercher ou créer une demande en attente
        PendingRegistration pending = pendingRegistrationRepository.findByEmailWithLock(createUserDTO.getEmail())
                .orElse(new PendingRegistration());

        if (pending.getTentativeEnvoi() >= MAX_RESEND_ATTEMPTS) {
            throw new RuntimeException("Trop de tentatives. Réessayez plus tard.");
        }

        // Mettre à jour les données
        pending.setEmail(createUserDTO.getEmail());
        pending.setPassword(encoder.encode(createUserDTO.getPassword()));
        pending.setNom(createUserDTO.getNom());
        pending.setPrenom(createUserDTO.getPrenom());
        pending.setSexe(createUserDTO.getSexe());
        pending.setTelephone(createUserDTO.getTelephone());
        pending.setTelephone1(createUserDTO.getTelephone1());
        Role userRole = roleRepository.findByLibelleRole(ERole.ROLE_CLIENT)
                .orElseThrow(() -> new RoleNotFoundException(ERole.ROLE_CLIENT.toString()));
        pending.setIdRole(userRole.getIdRole());
        pending.setFlagActif(false);
        pending.setDateNaissance(createUserDTO.getDateNaissance() != null ?
                createUserDTO.getDateNaissance() : null);
        pending.setCode(generateCode());
        pending.setCreation(Instant.now());
        pending.setExpiration(Instant.now().plus(CODE_EXPIRATION_MINUTES, MINUTES));

        // Incrémenter le compteur de tentatives si c'est un renvoi
        if (pending.getId() != null) {
            pending.setTentativeEnvoi(pending.getTentativeEnvoi() + 1);
        } else {
            pending.setTentativeEnvoi(1);
        }

        pendingRegistrationRepository.save(pending);

        // Envoyer le code (toujours)
        notificationService.envoyer(pending.getEmail(),pending.getNom(), pending.getCode());

        return buildSuccessResponse(HttpStatus.CREATED,"Utilisateur temporaire "+" créé avec succès. Un code d'activation vous a été envoyé sur "+createUserDTO.getEmail(), "TEMP_USER_CREATED",null);
    }
    @Transactional
    public ResponseEntity<?> activation(ActivateUserDTO activationCode) {

        PendingRegistration pending = pendingRegistrationRepository.findByCodeWithLock(activationCode.getCode())
                .orElseThrow(() -> new RuntimeException("Code de validation invalide"));

        if(Instant.now().isAfter(pending.getExpiration())){
            throw new RuntimeException("Votre code a expire");
        }

        if (userRepository.existsByEmail(pending.getEmail()) || userRepository.existsByTelephone(pending.getTelephone())) {
            pendingRegistrationRepository.delete(pending);
            throw new EmailAlreadyExistsException("Cet email ou numero de telephone est déjà utilisé");
        }
        User user = new User();
        user.setPassword(pending.getPassword());
        Role userRole = roleRepository.findByLibelleRole(ERole.ROLE_CLIENT)
                .orElseThrow(() -> new RoleNotFoundException(ERole.ROLE_CLIENT.toString()));
        user.setNom(pending.getNom());
        user.setPrenom(pending.getPrenom());
        user.setEmail(pending.getEmail());
        user.setDateNaissance(pending.getDateNaissance());
        user.setTelephone(pending.getTelephone());
        user.setRole(userRole);
        user.setFlagActif(true);
        user.setSexe(pending.getSexe());
        user.initTimestamp();
        userRepository.save(user);
        pendingRegistrationRepository.delete(pending);
        return  buildSuccessResponse(HttpStatus.OK, "Compte activé avec succès", "ACCOUNT_ACTIVATED",null);
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
        Optional<User> optionalUser = userRepository.findByEmail(username);
        return optionalUser.isPresent();
    }

    private ResponseEntity<?> buildSuccessResponse(HttpStatus status, String message, String code, Object data) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", message);
        response.put("code", code);
        response.put("timestamp", Instant.now().toString());

        // Si des données supplémentaires sont fournies, les ajouter
        if (data != null) {
            response.put("data", data);
        }

        return ResponseEntity.status(status).body(response);
    }

    private String generateCode() {
        Random random = new Random();
        int randomInteger = random.nextInt(999999);
        return String.format("%06d",randomInteger);
    }

    @Transactional
    public ResponseEntity<?> resendCode(ResendCodeEmailDTO resendCodeEmailDTO) {

        PendingRegistration pending = pendingRegistrationRepository.findByEmailWithLock(resendCodeEmailDTO.getEmail())
                .orElseThrow(() -> new RuntimeException("Aucune demande d'inscription en cours"));

        // Vérifier le nombre de tentatives
        if (pending.getTentativeEnvoi() >= MAX_RESEND_ATTEMPTS) {
            pendingRegistrationRepository.delete(pending);
            throw new RuntimeException("Trop de tentatives. Veuillez refaire une demande d'inscription.");
        }

        // Générer un nouveau code
        String newCode = generateCode();
        pending.setCode(newCode);
        pending.setCreation(Instant.now());
        pending.setExpiration(Instant.now().plus(CODE_EXPIRATION_MINUTES, MINUTES));
        pending.setTentativeEnvoi(pending.getTentativeEnvoi() + 1);

        pendingRegistrationRepository.save(pending);

        // Renvoyer le code
        notificationService.envoyer(pending.getEmail(),pending.getNom(), newCode);
        return buildSuccessResponse(HttpStatus.OK,"Un nouveau code a été envoyé à " +resendCodeEmailDTO.getEmail(),"CODE_RESENT",newCode);
    }

    @Transactional
    public void cleanExpiredPendingRegistrations() {
        pendingRegistrationRepository.deleteAllExpired(Instant.now());
    }

}
