package com.SQD20.SQD20.LIVEPROJECT.service.impl;

import com.SQD20.SQD20.LIVEPROJECT.domain.entites.AppUser;
import com.SQD20.SQD20.LIVEPROJECT.infrastructure.config.JwtAuthenticationFilter;
import com.SQD20.SQD20.LIVEPROJECT.infrastructure.config.JwtService;
import com.SQD20.SQD20.LIVEPROJECT.infrastructure.exception.InvalidAccessException;
import com.SQD20.SQD20.LIVEPROJECT.infrastructure.exception.PasswordNotFoundException;
import com.SQD20.SQD20.LIVEPROJECT.infrastructure.exception.UsernameNotFoundException;
import com.SQD20.SQD20.LIVEPROJECT.payload.request.AuthenticationRequest;
import com.SQD20.SQD20.LIVEPROJECT.payload.request.EmailDetails;
import com.SQD20.SQD20.LIVEPROJECT.payload.request.RegisterRequest;
import com.SQD20.SQD20.LIVEPROJECT.payload.request.UpdateUserRequest;
import com.SQD20.SQD20.LIVEPROJECT.payload.response.RegisterResponse;
import com.SQD20.SQD20.LIVEPROJECT.payload.response.AuthenticationResponse;
import com.SQD20.SQD20.LIVEPROJECT.payload.response.UserResponse;
import com.SQD20.SQD20.LIVEPROJECT.repository.UserRepository;
import com.SQD20.SQD20.LIVEPROJECT.service.EmailService;
import com.SQD20.SQD20.LIVEPROJECT.service.UserService;
import com.SQD20.SQD20.LIVEPROJECT.utils.EmailTemplate;
import com.SQD20.SQD20.LIVEPROJECT.utils.UserUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


@Service
@RequiredArgsConstructor
//@Slf4j
public class UserServiceImpl implements UserService {

    @Value("${baseUrl}")
    private String baseUrl;
    @Value("${frontend-host}")
    private String frontendHost;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;
    private final FileUploadServiceImpl fileUploadService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final HttpServletRequest request;

    private  final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);
    @Autowired
    private  HttpServletResponse response;

    private final Set<String> invalidatedTokens = ConcurrentHashMap.newKeySet();

    @Override
    public RegisterResponse register(@Valid RegisterRequest registerRequest) throws MessagingException, JsonProcessingException {

        // Validate email format
        String emailRegex = "^(.+)@(.+)$";
        Pattern pattern = Pattern.compile(emailRegex);
        Matcher matcher = pattern.matcher(registerRequest.getEmail());
        if (!matcher.matches()) {
            return RegisterResponse.builder()
                    .responseCode(UserUtils.INVALID_EMAIL_FORMAT_CODE)
                    .responseMessage(UserUtils.INVALID_EMAIL_FORMAT_MESSAGE)
                    .build();
        }

        // Validate email domain
        String[] emailParts = registerRequest.getEmail().split("\\.");
        if (emailParts.length < 2 || emailParts[emailParts.length - 1].length() < 2) {
            System.out.println("Invalid email domain. Email parts: " + Arrays.toString(emailParts));

            return RegisterResponse.builder()
                    .responseCode(UserUtils.INVALID_EMAIL_DOMAIN_CODE)
                    .responseMessage(UserUtils.INVALID_EMAIL_DOMAIN_MESSAGE)
                    .build();
        }

        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            return RegisterResponse.builder()
                    .responseCode(UserUtils.ACCOUNT_EXISTS_CODE)
                    .responseMessage(UserUtils.ACCOUNT_EXISTS_MESSAGE)
                    .build();
        }

        String encodedPassword = passwordEncoder.encode(registerRequest.getPassword());

        AppUser newUser = AppUser.builder()
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                .password(encodedPassword) // Encode the password
                .phoneNumber(registerRequest.getPhoneNumber())
                .isEnabled(false)
                .build();
        AppUser savedUser = userRepository.save(newUser);
        String jwtToken = jwtService.generateToken(newUser);
        String link = EmailTemplate.getVerificationUrl(baseUrl, jwtToken);
        EmailDetails emailDetails = EmailDetails.builder()
                .recipient(savedUser.getEmail())
                .subject("ACCOUNT VERIFICATION")
                .messageBody(EmailTemplate.getEmailMessage(savedUser.getFirstName(), baseUrl, jwtToken))
                .build();

        emailService.sendHtmlMessageToVerifyEmail(emailDetails, newUser.getFirstName(), link);
        return RegisterResponse.builder()
                .responseCode(UserUtils.ACCOUNT_CREATION_SUCCESS_CODE)
                .responseMessage(UserUtils.ACCOUNT_CREATION_SUCCESS_MESSAGE)
                .build();
    }


    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest request) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        AppUser user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        user.setToken(jwtToken);
        return AuthenticationResponse.builder()
                .id(user.getId())
                .responseCode(UserUtils.LOGIN_SUCCESS_CODE)
                .responseMessage(UserUtils.LOGIN_SUCCESS_MESSAGE)
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .accessToken(jwtToken)
                .build();
    }

    @Override
    public String verifyEmail(String token) {
        String username = jwtService.getUserName(token);
//        log.info(username);
        if (username != null) {
            Optional<AppUser> user = userRepository.findByEmail(username);
//            log.info(username);
            if (user.isPresent()) {
                if (user.get().isEnabled()) {
                    return "User has been verified!";
                } else {
                    user.get().setIsEnabled(true);
                    userRepository.save(user.get());
//                    log.info("Got to verification line");
                    return "Email Verified";
                }

            } else {
                return "User does not exist";
            }
        }
        return "Invalid token or broken link";
    }

    @Override
    public ResponseEntity<?> resendEmailVerification(String email) {
        // Check if the user exists
        Optional<AppUser> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isEmpty()) {
            return ResponseEntity.badRequest().body("User with the provided email does not exist.");
        }
        AppUser user = optionalUser.get();

        // Check if the user's email is already verified
        if (user.isEnabled()) {
            return ResponseEntity.badRequest().body("User's email is already verified.");
        }

        // Generate a new verification token
        String jwtToken = jwtService.generateToken(user);
        String link = EmailTemplate.getVerificationUrl(baseUrl,jwtToken);

        // Send the verification email
        EmailDetails emailDetails = EmailDetails.builder()
                .recipient(user.getEmail())
                .subject("ACCOUNT VERIFICATION")
                .messageBody(EmailTemplate.getEmailMessage(user.getFirstName(), baseUrl, jwtToken))
                .build();

        try {
            emailService.sendHtmlMessageToVerifyEmail(emailDetails, user.getFirstName(),link);
            return ResponseEntity.ok().body("Verification email resent successfully.");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to resend verification email. Please try again later.");
        }
    }

    @Override
    public UserResponse editUser(Long id, UpdateUserRequest updateUserRequest) {
        AppUser appUser = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("No User associated with " + id));
        appUser.setFirstName(updateUserRequest.getFirstName());
        appUser.setLastName(updateUserRequest.getLastName());
        appUser.setPhoneNumber(updateUserRequest.getPhoneNumber());
        userRepository.save(appUser);
        return UserResponse.builder()
                .responseMessage(UserUtils.USER_UPDATE_MESSAGE)
                .firstName(appUser.getFirstName())
                .lastName(appUser.getLastName())
                .phoneNumber(appUser.getPhoneNumber())
                .build();
    }

    @Override
    public UserResponse viewUser(Long id) {
        AppUser viewUser = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return UserResponse.builder()
                .responseMessage(UserUtils.USER_DETAILS_MESSAGE)
                .firstName(viewUser.getFirstName())
                .lastName(viewUser.getLastName())
                .phoneNumber(viewUser.getPhoneNumber())
                .email(viewUser.getEmail())
                .build();
    }

    @Override
    public String resetPassword(String email, String oldPassword, String newPassword) {
        AppUser user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("No User with this email: " + email));
        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new PasswordNotFoundException("Old password does not match the current password!");
        } else {
            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);
            return "Your Password has been reset successfully, login with the new password ";
        }
    }

    @Override
    public ResponseEntity<?> forgotPasswordEmail(String email) {
            Optional<AppUser> optionalAppUser = userRepository.findByEmail(email);
            if (optionalAppUser.isEmpty()) {
                return ResponseEntity.badRequest().body("User with the provided email does not exist.");
            }
            AppUser user = optionalAppUser.get();
            try {
                String resetToken = jwtService.generateToken(user);
                String link = EmailTemplate.getForgotPasswordVerificationUrl(baseUrl, resetToken);
                EmailDetails emailDetails = EmailDetails.builder()
                        .recipient(user.getEmail())
                        .subject("Reset Your Password")
                        .messageBody(EmailTemplate.getEmailMessage(user.getFirstName(), baseUrl, resetToken))
                        .build();
                //emailService.sendEmailAlert(emailDetails);
                emailService.sendHtmlMessageForResetPassword(emailDetails,user.getFirstName(),link);
                return ResponseEntity.ok().body("Password reset email sent successfully.");
            } catch (Exception e) {
                e.printStackTrace();
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Failed to send password reset email. Please try again later.");
            }
        }

    @Override
    public String verifyForgotPasswordEmail(String token) throws IOException {
        String username = jwtService.getUserName(token);
        if (username != null) {
            Optional<AppUser> userOptional = userRepository.findByEmail(username);
            if (userOptional.isPresent()) {
                AppUser user = userOptional.get();
                // Check if the token is valid for resetting the password
                if (jwtService.validateToken(token)) {
                    // If the token is valid, return appropriate message
                    String url = frontendHost + "/reset-password?email=" + user.getEmail();
                    response.sendRedirect(url);
                    return "Email Verified for Password Reset";
                } else {
                    // If the token is invalid, return appropriate message
                    return "Invalid or Expired Token";
                }
            } else {
                // If the user does not exist, return appropriate message
                return "User does not exist";
            }
        } else {
            return "Invalid Token or Broken Link";
        }
    }



    @Override
    public String forgotPassword(String email, String newPassword, String confirmPassword) {
        Optional<AppUser> optionalAppUser = userRepository.findByEmail(email);
        if (optionalAppUser.isEmpty()) {
            return "User with the provided email does not exist.";
        }
        AppUser user = optionalAppUser.get();
        if (!newPassword.equals(confirmPassword)) {
            return "New password and confirm password do not match.";
        }
        String encryptedPassword = passwordEncoder.encode(newPassword);
        userRepository.updateUserPassword(user.getEmail(), encryptedPassword);
        return "Password reset successfully. You can now login with your new password.";
    }

    public UserDetails loadUserByUsername(String username) {

        Optional<AppUser> optionalUser = userRepository.findByEmail(username);
        if (optionalUser.isEmpty()) {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
        AppUser user = optionalUser.get();

        return User.builder()
                .username(user.getEmail())
                .password(user.getPassword())
                .accountExpired(!user.isAccountNonExpired())
                .accountLocked(!user.isAccountNonLocked())
                .credentialsExpired(!user.isCredentialsNonExpired())
                .disabled(!user.isEnabled())
                .build();
    }

    @Override
    public ResponseEntity<UserResponse<String>> uploadProfilePicture(MultipartFile profilePics) {
        String token = jwtAuthenticationFilter.getTokenFromRequest(request);
        String email = jwtService.getUserName(token);

        Optional<AppUser> userOptional = userRepository.findByEmail(email);
        String file_url = "";

        try {
            if (userOptional.isPresent()){
                file_url = fileUploadService.uploadFile(profilePics);

                AppUser user = userOptional.get();
                user.setProfilePicture(file_url);

                userRepository.save(user);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return ResponseEntity.ok(
                new UserResponse<>(
                        "Uploaded Successfully",
                        file_url != null ? file_url : ""
                )
        );
    }

    public String logout() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication authentication = securityContext.getAuthentication();
        if (authentication != null){
            String email = authentication.getName();
            Optional<AppUser> appUser = userRepository.findByEmail(email);
            if(appUser.isPresent()){
                AppUser existingUser = appUser.get();
                existingUser.setToken(null);
                userRepository.save(existingUser);
                securityContext.setAuthentication(null);
                SecurityContextHolder.clearContext();
                return "logout successfully";
            }else {
                throw new InvalidAccessException("Invalid User");
            }

        }
        throw new InvalidAccessException("Invalid access");
    }
}
