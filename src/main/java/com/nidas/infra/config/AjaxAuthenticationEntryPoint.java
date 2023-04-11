package com.nidas.infra.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nidas.modules.main.ErrorResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;

public class AjaxAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

    private ObjectMapper objectMapper;

    public AjaxAuthenticationEntryPoint(String loginFormUrl) {
        super(loginFormUrl);
        this.objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        String ajaxHeader = request.getHeader("X-Requested-With");
        boolean isAjax = ajaxHeader != null && ajaxHeader.equals("XMLHttpRequest");

        if (isAjax) {
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            objectMapper.writeValue(response.getOutputStream(), makeErrorResponse("권한이 없습니다.", HttpServletResponse.SC_FORBIDDEN));
        } else {
            super.commence(request, response, authException);
        }
    }

    private ErrorResponse makeErrorResponse(String message, int status) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .status(status)
                .message(message)
                .timestamp(LocalDateTime.now())
                .build();
        return errorResponse;
    }

}
