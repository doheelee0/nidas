package com.nidas.modules.product;

import com.fasterxml.jackson.annotation.JsonCreator;
import lombok.Getter;

@Getter
public enum Size {

    /* KIDS */
    EIGHTY(80),
    NINETY(90),
    ONE_HUNDRED(100),
    ONE_HUNDRED_TEN(110),
    ONE_HUNDRED_TWENTY(120),
    ONE_HUNDRED_THIRTY(130),
    ONE_HUNDRED_FORTY(140),
    ONE_HUNDRED_FIFTY(150),
    ONE_HUNDRED_SIXTY(160),
    ONE_HUNDRED_SIXTY_FIVE(165),
    ONE_HUNDRED_SEVENTY(170),
    ONE_HUNDRED_SEVENTY_FIVE(175),
    ONE_HUNDRED_EIGHTY(180),
    ONE_HUNDRED_EIGHTY_FIVE(185),
    ONE_HUNDRED_NINETY(190),
    ONE_HUNDRED_NINETY_FIVE(195),
    TWO_HUNDRED(200),
    TWO_HUNDRED_FIVE(205),
    TWO_HUNDRED_TEN(210),
    TWO_HUNDRED_FIFTEEN(215),

    /* KIDS, WOMEN */
    TWO_HUNDRED_TWENTY(220),
    TWO_HUNDRED_TWENTY_FIVE(225),
    TWO_HUNDRED_THIRTY(230),
    TWO_HUNDRED_THIRTY_FIVE(235),
    TWO_HUNDRED_FORTY(240),
    TWO_HUNDRED_FORTY_FIVE(245),

    /* WOMEN, MEN */
    TWO_HUNDRED_FIFTY(250),
    TWO_HUNDRED_FIFTY_FIVE(255),
    TWO_HUNDRED_SIXTY(260),
    TWO_HUNDRED_SIXTY_FIVE(265),
    TWO_HUNDRED_SEVENTY(270),
    TWO_HUNDRED_SEVENTY_FIVE(275),
    TWO_HUNDRED_EIGHTY(280),
    TWO_HUNDRED_EIGHTY_FIVE(285),
    TWO_HUNDRED_NINETY(290),
    TWO_HUNDRED_NINETY_FIVE(295),
    THREE_HUNDRED(300);

    private int value;

    Size(int value) {
        this.value = value;
    }

    @JsonCreator
    public static Size from(String s) {
        try {
            int value = Integer.parseInt(s);
            for (Size size : Size.values()) {
                if (size.value == value) return size;
            }
            return null;
        } catch (IllegalArgumentException | NullPointerException e) {
            return null;
        }
    }
}
