package com.nidas.modules.product;

import com.fasterxml.jackson.annotation.JsonCreator;

public enum Color {

    BEIGE, BLACK, BLUE, BROWN, GOLD, GREEN, GRAY, PINK, PURPLE, RED, SILVER, WHITE, YELLOW;

    @JsonCreator
    public static Color from(String s) {
        try {
            return Color.valueOf(s.toUpperCase());
        } catch (IllegalArgumentException | NullPointerException e) {
            return null;
        }
    }

    public static boolean contains(String s) {
        for (Color c : Color.values()) {
            if (c.name().equalsIgnoreCase(s)) return true;
        }
        return false;
    }

}
