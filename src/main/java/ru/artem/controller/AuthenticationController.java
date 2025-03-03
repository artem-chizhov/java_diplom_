package ru.artem.controller;

import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import ru.artem.dto.request.AuthenticationRQ;
import ru.artem.dto.response.AuthenticationRS;
import ru.artem.service.AuthenticationService;

@RestController
@AllArgsConstructor
public class AuthenticationController {

    private AuthenticationService authenticationService;

    @PostMapping("/login")
    public AuthenticationRS login(@RequestBody AuthenticationRQ authenticationRQ) {
        return authenticationService.login(authenticationRQ);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("auth-token") String authToken) {
        authenticationService.logout(authToken);
        return ResponseEntity.ok(HttpStatus.OK);
    }
}