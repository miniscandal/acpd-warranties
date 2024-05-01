package com.authorizedcellphonedealer.acpdwarranties.middlewares;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.authorizedcellphonedealer.acpdwarranties.services.AuthTokenService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class SecurityFilter extends OncePerRequestFilter {
    private final Logger log = LoggerFactory.getLogger(SecurityFilter.class);
    private AuthTokenService authTokenService;

    public SecurityFilter(AuthTokenService authTokenService) {
        this.authTokenService = authTokenService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        log.info("Filter");
        boolean isValidToken = false;
        try {
            authTokenService.evie();
            isValidToken = authTokenService.validateToken(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (isValidToken) {
            log.info("token is valid");
        } else {
            log.info("token is not valid");
        }
    }
}
