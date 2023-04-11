package com.nidas.modules.faq;

import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.Length;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Getter @Setter
public class FaqForm {

    @NotNull(message = "종류를 선택해주세요.")
    private FaqType type;

    @NotBlank(message = "제목을 입력해주세요.")
    @Length(max = 100, message = "100자 이하로 입력해주세요.")
    private String title;

    @NotBlank(message = "내용을 입력해주세요.")
    private String content;

}
