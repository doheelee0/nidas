package com.nidas.modules.cart.form;

import lombok.Getter;
import lombok.Setter;

import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import java.util.List;

@Getter @Setter
public class CartForm {

    @Valid
    @NotEmpty(message = "장바구니에 추가하려는 상품이 없습니다.")
    private List<CartItemForm> itemList;

    private boolean orderCheck;

}
