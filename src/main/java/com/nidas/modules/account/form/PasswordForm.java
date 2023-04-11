package com.nidas.modules.account.form;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

@Getter @Setter
public class PasswordForm {

    @NotBlank(message = "현재 비밀번호를 입력해주세요.")
    private String currentPassword;

    @NotBlank(message = "새 비밀번호를 입력해주세요.")
    @Pattern(
            regexp = "^(?=.*[a-zA-Z])(?=.*[0-9])(?=.*[!@#$%^&*_-])[a-zA-Z0-9!@#$%^&*_-]{8,20}$",
            message = "영문자, 숫자, 특수문자를 반드시 포함하여 공백없이 8자 이상 입력해 주세요."
    )
    private String newPassword1;

    private String newPassword2;

}
