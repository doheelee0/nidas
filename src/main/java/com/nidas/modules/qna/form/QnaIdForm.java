package com.nidas.modules.qna.form;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotNull;

@Setter @Getter
public class QnaIdForm {

    @NotNull(message = "존재하지 않는 Q&A입니다.")
    private Long qnaId;

    @NotNull(message = "존재하지 않는 회원입니다.")
    private Long accountId;

}
