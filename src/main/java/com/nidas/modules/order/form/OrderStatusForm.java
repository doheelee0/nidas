package com.nidas.modules.order.form;

import com.nidas.modules.order.OrderStatus;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotNull;

@Setter @Getter
public class OrderStatusForm {

    @NotNull(message = "잘못된 주문상태 값입니다.")
    private OrderStatus orderStatus;

    @NotNull(message = "존재하지 않는 회원입니다.")
    private Long accountId;

}
