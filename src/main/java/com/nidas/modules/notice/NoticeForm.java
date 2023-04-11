package com.nidas.modules.notice;

import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.Length;

import javax.validation.constraints.NotBlank;

@Getter @Setter
public class NoticeForm {

    @NotBlank(message = "제목을 입력해주세요.")
    @Length(max = 100, message = "100자 이하로 입력해주세요.")
    private String title;

    @NotBlank(message = "내용을 입력해주세요.")
    private String content;

}
