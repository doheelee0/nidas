package com.nidas.modules.account;

import com.nidas.infra.config.TestProperties;
import com.nidas.modules.account.form.SignUpForm;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

@RequiredArgsConstructor
public class WithAccountSecurityContextFactory implements WithSecurityContextFactory<WithAccount> {

    private final AccountService accountService;
    private final TestProperties testProperties;

    @Override
    public SecurityContext createSecurityContext(WithAccount withAccount) {
        String email = withAccount.value();
        Authority authority = withAccount.authority();

        SignUpForm signUpForm = new SignUpForm();
        signUpForm.setEmail(email);
        signUpForm.setPassword1(testProperties.getPassword());
        signUpForm.setPassword2(testProperties.getPassword());
        signUpForm.setName(testProperties.getName());
        signUpForm.setGender(Gender.valueOf(testProperties.getGender()));
        signUpForm.setBirthday(LocalDate.parse(testProperties.getBirthday(), DateTimeFormatter.ofPattern("yyyy-MM-dd")));
        signUpForm.setPhoneNumber(testProperties.getPhoneNumber());
        Account account = accountService.processNewAccount(signUpForm);
        account.setAuthority(authority);
        account.completeSignUp();

        UserDetails principal = accountService.loadUserByUsername(email);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(principal, principal.getPassword(), principal.getAuthorities());
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(token);
        return context;
    }
}
