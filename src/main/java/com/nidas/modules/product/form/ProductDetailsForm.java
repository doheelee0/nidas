package com.nidas.modules.product.form;

import com.nidas.modules.product.Color;
import com.nidas.modules.product.Size;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;

@Getter @Setter
public class ProductDetailsForm {

    @NotNull(message = "잘못된 컬러 값입니다.")
    private Color color;

    @NotNull(message = "잘못된 사이즈 값입니다.")
    private Size size;

    @NotNull(message = "재고를 기재해주세요.")
    @Min(value = 0, message = "재고는 0개 이상이어야 합니다.")
    private Integer stock;

}
