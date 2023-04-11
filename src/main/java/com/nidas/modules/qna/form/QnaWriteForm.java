package com.nidas.modules.qna.form;

import com.nidas.modules.qna.QnaType;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotNull;

@Getter @Setter
public class QnaWriteForm {

    @NotNull(message = "문의종류를 선택해주세요.")
    private QnaType type;

    @NotNull(message = "문의내용을 입력해주세요.")
    private String content;

    private boolean secret;

}
