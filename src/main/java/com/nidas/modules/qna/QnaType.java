package com.nidas.modules.qna;

import lombok.Getter;

@Getter
public enum QnaType {

    PRODUCT_QNA("상품문의"),
    RESTOCK_QNA("재입고문의"),
    SIZE_QNA("사이즈문의"),
    DELIVERY_QNA("배송문의"),
    ETC_QNA("기타");

    private String name;

    QnaType(String name) {
        this.name = name;
    }

    public static boolean contains(String s) {
        for (QnaType q : QnaType.values()) {
            if (q.name().equalsIgnoreCase(s)) return true;
        }
        return false;
    }

}
