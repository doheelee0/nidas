package com.nidas.modules.product;

import com.fasterxml.jackson.annotation.JsonCreator;

public enum MainCategory {

    MEN, WOMEN, KIDS;

    @JsonCreator
    public static MainCategory from(String s) {
        try {
            return MainCategory.valueOf(s.toUpperCase());
        } catch (IllegalArgumentException | NullPointerException e) {
            return null;
        }
    }

}
