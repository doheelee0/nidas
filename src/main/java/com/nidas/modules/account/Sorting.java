package com.nidas.modules.account;

import lombok.Getter;

@Getter
public enum Sorting {

    EMAIL("이메일순"),
    NAME("이름순"),
    TOTAL_ORDER("주문숫자순"),
    TOTAL_PAYMENT("주문금액순"),
    MEMBERSHIP("멤버쉽등급순"),
    LATEST_LOGIN_DATE_TIME("최근접속일순"),
    NEW_JOINED_DATE_TIME("최신가입일순"),
    OLD_JOINED_DATE_TIME("오래된가입일순");

    private String name;

    Sorting(String name) {
        this.name = name;
    }

}
