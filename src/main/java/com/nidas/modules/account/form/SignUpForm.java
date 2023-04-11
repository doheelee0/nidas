package com.nidas.modules.account.form;

import com.nidas.modules.account.Gender;
import com.nidas.modules.account.IsAfter;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.Length;
import org.springframework.format.annotation.DateTimeFormat;

import javax.validation.constraints.*;
import java.time.LocalDate;

@Getter @Setter
public class SignUpForm {

    @NotBlank(message = "이메일을 입력해주세요.")
    @Email(message = "이메일 형식이어야 합니다.")
    @Length(max = 100, message = "100자 이하로 입력해주세요.")
    private String email;

    @NotBlank(message = "비밀번호를 입력해주세요.")
    @Pattern(
            regexp = "^(?=.*[a-zA-Z])(?=.*[0-9])(?=.*[!@#$%^&*_-])[a-zA-Z0-9!@#$%^&*_-]{8,20}$",
            message = "영문자, 숫자, 특수문자를 반드시 포함하여 공백없이 8자 이상 입력해 주세요."
    )
    private String password1;

    private String password2;

    @NotBlank(message = "이름을 입력해주세요.")
    @Pattern(
            regexp = "^(([a-zA-Z]{1,50})|([가-힣]{1,50}))$",
            message = "영문자, 한글로 입력해주세요."
    )
    private String name;

    @NotNull(message = "성별을 선택해주세요.")
    private Gender gender;

    @NotNull(message = "생년월일을 선택해주세요.")
    @Past
    @IsAfter
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE, pattern = "yyyy-MM-dd")
    private LocalDate birthday;

    @NotBlank(message = "휴대폰번호를 입력해주세요.")
    @Pattern(
            regexp = "^(01[016789])([0-9]{3,4})([0-9]{4})$",
            message = "(-) 없이 휴대폰번호 10자리 또는 11자리를 입력해주세요."
    )
    private String phoneNumber;

}
