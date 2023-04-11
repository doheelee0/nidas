package com.nidas.modules.account.validator;

import com.nidas.modules.account.Account;
import com.nidas.modules.account.UserPrincipal;
import com.nidas.modules.account.form.PasswordForm;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

@Component
@RequiredArgsConstructor
public class PasswordFormValidator implements Validator {

    private final PasswordEncoder passwordEncoder;

    @Override
    public boolean supports(Class<?> clazz) {
        return clazz.isAssignableFrom(PasswordForm.class);
    }

    @Override
    public void validate(Object target, Errors errors) {
        PasswordForm passwordForm = (PasswordForm) target;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Account account = ((UserPrincipal) authentication.getPrincipal()).getAccount();

        // 기존 패스워드 확인 검사
        if (!passwordEncoder.matches(passwordForm.getCurrentPassword(), account.getPassword())) {
            errors.rejectValue("currentPassword", "invalid_currentPassword", new Object[]{passwordForm.getCurrentPassword()}, "비밀번호가 틀립니다.");
        }
        // 새 패스워드 일치 검사
        if (!passwordForm.getNewPassword1().equals(passwordForm.getNewPassword2())) {
            errors.rejectValue("newPassword2", "invalid_newPassword2", new Object[]{passwordForm.getNewPassword2()}, "비밀번호가 일치하지 않습니다.");
        }
    }

}
