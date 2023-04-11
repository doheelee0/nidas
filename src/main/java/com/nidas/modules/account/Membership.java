package com.nidas.modules.account;

import lombok.Getter;

@Getter
public enum Membership {

    BRONZE("브론즈", 0, 99999, "5,000원 할인 쿠폰 1장 지급"),
    SILVER("실버", 100000, 199999, "10,000원 할인 쿠폰 1장 지급"),
    GOLD("골드", 200000, 499999, "10,000원 할인 3장 지급"),
    DIAMOND("다이아", 500000, 999999, "20,000원 할인 쿠폰 3장 지급"),
    VIP("VIP", 1000000, null, "30,000원 할인 쿠폰 3장 지급");

    private String name;

    private Integer lowerBound;

    private Integer upperBound;

    private String benefits;

    Membership(String name, Integer lowerBound, Integer upperBound, String benefits) {
        this.name = name;
        this.lowerBound = lowerBound;
        this.upperBound = upperBound;
        this.benefits = benefits;
    }

    public static Membership getEnumByBound(Long value) {
        for (Membership m : Membership.values()) {
            if (m.lowerBound <= value && (m.upperBound == null || m.upperBound >= value)) return m;
        }
        return null;
    }

    public static Membership from(String s) {
        try {
            return Membership.valueOf(s.toUpperCase());
        } catch (IllegalArgumentException | NullPointerException e) {
            return null;
        }
    }

}
