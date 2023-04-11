package com.nidas.modules.cart.form;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.Max;
import javax.validation.constraints.Min;

@Getter @Setter
public class QuantityForm {

    @Min(value = 1, message = "최소 1개여야 합니다.")
    @Max(value = 9, message = "최대 9개여야 합니다.")
    private Integer quantity;

}
