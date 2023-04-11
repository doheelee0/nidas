package com.nidas.modules.account;

import com.fasterxml.jackson.annotation.JsonCreator;
import lombok.Getter;

@Getter
public enum Gender {

    M("남"),
    F("여"),
    U("선택안함");

    private String name;

    Gender(String name) {
        this.name = name;
    }

    @JsonCreator
    public static Gender from(String s) {
        try {
            return Gender.valueOf(s.toUpperCase());
        } catch (IllegalArgumentException | NullPointerException e) {
            return null;
        }
    }

}
