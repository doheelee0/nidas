package com.nidas.modules.order;

import com.fasterxml.jackson.annotation.JsonCreator;
import lombok.Getter;

import java.util.EnumSet;

@Getter
public enum OrderStatus {

    PAID("결제완료"),
    CANCELED("취소됨"),
    PRODUCT_READY("상품준비"),
    DELIVERING("배송중"),
    DELIVERED("배송완료"),
    EXCHANGING("교환요청"),
    EXCHANGED("교환완료"),
    RETURNING("환불요청"),
    RETURNED("환불완료");

    private String name;

    OrderStatus(String name) {
        this.name = name;
    }

    public static EnumSet<OrderStatus> returnsValues() {
        return EnumSet.of(EXCHANGING, EXCHANGED, RETURNING, RETURNED);
    }

    public static boolean contains(String s) {
        for (OrderStatus o : OrderStatus.values()) {
            if (o.name().equalsIgnoreCase(s)) return true;
        }
        return false;
    }

    @JsonCreator
    public static OrderStatus from(String s) {
        try {
            return OrderStatus.valueOf(s.toUpperCase());
        } catch (IllegalArgumentException | NullPointerException e) {
            return null;
        }
    }

}
