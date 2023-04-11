package com.nidas.modules.cart.form;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotEmpty;
import java.util.Set;

@Getter @Setter
public class CartIdListForm {

    @NotEmpty(message = "선택된 장바구니 상품이 없습니다.")
    private Set<Long> idList;

}
