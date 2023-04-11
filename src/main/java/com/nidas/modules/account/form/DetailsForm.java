package com.nidas.modules.account.form;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.nidas.modules.account.Gender;
import com.nidas.modules.account.IsAfter;
import lombok.Getter;
import lombok.Setter;
import org.springframework.format.annotation.DateTimeFormat;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Past;
import javax.validation.constraints.Pattern;
import java.time.LocalDate;

@Getter @Setter
public class DetailsForm {

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
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private LocalDate birthday;

    @NotBlank(message = "휴대폰번호를 입력해주세요.")
    @Pattern(
            regexp = "^(01[016789])([0-9]{3,4})([0-9]{4})$",
            message = "(-) 없이 휴대폰번호 10자리 또는 11자리를 입력해주세요."
    )
    private String phoneNumber;

    private String address1;

    private String address2;

    private String address3;

}
