package com.nidas.modules.order.event;

import com.nidas.modules.order.OrderDetails;
import lombok.Getter;

@Getter
public class OrderStatusChangedEvent {

    private OrderDetails orderDetails;

    private String message;

    public OrderStatusChangedEvent(OrderDetails orderDetails) {
        this.orderDetails = orderDetails;
        this.message = orderDetails.getOrder().getOrderNumber() + "의 주문상품이 '"
                + orderDetails.getStatus().getName() + "'상태로 변경되었습니다.";
    }
}
