package com.nidas.modules.faq;

import com.fasterxml.jackson.annotation.JsonCreator;
import lombok.Getter;

@Getter
public enum FaqType {

    ORDER_PAYMENT_FAQ("주문결제"),
    DELIVERY_FAQ("배송"),
    CANCEL_RETURN_EXCHANGE_FAQ("취소/반품/교환"),
    ETC_FAQ("기타");

    private String name;

    FaqType(String name) {
        this.name = name;
    }

    @JsonCreator
    public static FaqType from(String s) {
        try {
            return FaqType.valueOf(s.toUpperCase());
        } catch (IllegalArgumentException | NullPointerException e) {
            return null;
        }
    }

}
