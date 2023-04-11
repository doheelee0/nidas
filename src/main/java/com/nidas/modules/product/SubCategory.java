package com.nidas.modules.product;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.nidas.infra.exception.InvalidParameterException;
import lombok.Getter;

@Getter
public enum SubCategory {

    LIFESTYLE("라이프스타일"),
    RUNNING("러닝"),
    BASKETBALL("농구"),
    COURT("코트"),
    SKATE_CANVAS("스케이트 & 캔버스"),
    SANDAL_SLIPPER("샌들 & 슬리퍼");

    private String name;

    SubCategory(String name) {
        this.name = name;
    }

    public static SubCategory nameOf(String name) {
        for (SubCategory subCategory : SubCategory.values()) {
            if (subCategory.name.equals(name)) return subCategory;
        }
        throw new InvalidParameterException("No enum constant SubCategory." + name);
    }

    @JsonCreator
    public static SubCategory from(String s) {
        try {
            return SubCategory.valueOf(s.toUpperCase());
        } catch (IllegalArgumentException | NullPointerException e) {
            return null;
        }
    }
}
