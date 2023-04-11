package com.nidas.modules.product;

import lombok.Getter;

@Getter
public enum Sorting {

    SALES("판매량순"),
    REVIEW("리뷰순"),
    RATING("평점순"),
    NAME("이름순"),
    NEW("신상품순"),
    OLD("오래된순"),
    LOWER_PRICE("낮은가격순"),
    HIGH_PRICE("높은가격순"),
    FAVORITES("즐겨찾기순");

    private String name;

    Sorting(String name) {
        this.name = name;
    }

}
