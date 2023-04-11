package com.nidas.modules.returns.form;

import com.nidas.modules.returns.ReturnsType;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Getter @Setter
public class ReturnsForm {

    @NotNull(message = "반품사유를 선택해주세요.")
    private ReturnsType type;

    @NotBlank(message = "반품내용을 입력해주세요.")
    private String content;

    private String image;

}
