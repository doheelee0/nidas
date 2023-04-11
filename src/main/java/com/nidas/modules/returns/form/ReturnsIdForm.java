package com.nidas.modules.returns.form;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotNull;

@Setter @Getter
public class ReturnsIdForm {

    @NotNull(message = "해당하는 반품신청이 존재하지 않습니다.")
    private Long returnsId;

    @NotNull(message = "존재하지 않는 회원입니다.")
    private Long accountId;

}
