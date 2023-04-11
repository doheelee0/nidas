package com.nidas.modules.product.form;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotNull;

@Getter @Setter
public class ProductImageForm {

    @NotNull(message = "잘못된 이미지입니다.")
    private String image;

}
