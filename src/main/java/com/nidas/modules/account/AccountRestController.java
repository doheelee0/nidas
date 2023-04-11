package com.nidas.modules.account;

import com.nidas.infra.exception.InvalidParameterException;
import com.nidas.modules.account.form.DetailsForm;
import com.nidas.modules.account.form.PasswordForm;
import com.nidas.modules.account.validator.PasswordFormValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequiredArgsConstructor
public class AccountRestController {

    private final AccountService accountService;
    private final PasswordFormValidator passwordFormValidator;

    @InitBinder("passwordForm")
    public void validatePasswordForm(WebDataBinder webDataBinder) {
        webDataBinder.addValidators(passwordFormValidator);
    }

    @PostMapping("/resend/verification-code")
    public ResponseEntity resendVerificationCode(@CurrentAccount Account account) {
        if (account.isEmailVerified()) {
            throw new InvalidParameterException("이미 인증된 상태입니다.");
        }
        if (!account.canSendEmailCheckToken()) {
            throw new InvalidParameterException(account.getEmailCheckTokenCoolTime() + "분 후에 메일을 보낼 수 있습니다.");
        }
        accountService.resendEmailCheckToken(account);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/mypage/edit/info/details")
    public ResponseEntity editDetailsInfo(@CurrentAccount Account account, @RequestBody @Valid DetailsForm detailsForm) {
        accountService.editDetailsInfo(account, detailsForm);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/mypage/edit/info/password")
    public ResponseEntity editPasswordInfo(@CurrentAccount Account account, @RequestBody @Valid PasswordForm passwordForm) {
        accountService.editPasswordInfo(account, passwordForm);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/mypage/edit/info/web-reception")
    public ResponseEntity editWebReceptionInfo(@CurrentAccount Account account) {
        accountService.toggleWebReceptionInfo(account);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/mypage/edit/info/email-reception")
    public ResponseEntity editEmailReceptionInfo(@CurrentAccount Account account) {
        accountService.toggleEmailReceptionInfo(account);
        return ResponseEntity.ok().build();
    }

}
