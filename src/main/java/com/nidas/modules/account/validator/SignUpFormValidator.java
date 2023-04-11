package com.nidas.modules.account.validator;

import com.nidas.modules.account.AccountRepository;
import com.nidas.modules.account.form.SignUpForm;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

@Component
@RequiredArgsConstructor
public class SignUpFormValidator implements Validator {

    private final AccountRepository accountRepository;

    @Override
    public boolean supports(Class<?> clazz) {
        return clazz.isAssignableFrom(SignUpForm.class);
    }

    @Override
    public void validate(Object target, Errors errors) {
        SignUpForm signUpForm = (SignUpForm) target;
        // 이메일 중복 검사
        if (accountRepository.existsByEmail(signUpForm.getEmail())) {
            errors.rejectValue("email", "invalid.email", new Object[]{signUpForm.getEmail()}, "이미 존재하는 이메일입니다.");
        }
        // 패스워드 일치 검사
        if (!signUpForm.getPassword1().equals(signUpForm.getPassword2())) {
            errors.rejectValue("password2", "invalid.password2", new Object[]{signUpForm.getPassword2()}, "비밀번호가 일치하지 않습니다.");
        }
    }
}
