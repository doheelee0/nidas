package com.nidas.modules.returns;

import com.fasterxml.jackson.annotation.JsonCreator;
import lombok.Getter;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Getter
public enum ReturnsType {

    /* 교환 */
    EXCHANGE_MIND_CHANGED("변심", "E"),
    EXCHANGE_DELIVERED_BROKEN("파손된 상태로 배송됨", "E"),
    EXCHANGE_OTHER_PRODUCT("다른 물품 요청", "E"),
    EXCHANGE_SIZE("사이즈 변경", "E"),
    EXCHANGE_ETC("기타", "E"),

    /* 환불 */
    RETURN_MIND_CHANGED("변심", "R"),
    RETURN_DISSATISFACTION("상품 및 서비스 불만족", "R"),
    RETURN_DELIVERED_BROKEN("파손된 상태로 배송됨", "R"),
    RETURN_DELIVERED_OTHER_PRODUCT("다른 상품이 배송됨", "R"),
    RETURN_ETC("기타", "R");

    private String name;

    private String simpleType;

    ReturnsType(String name, String simpleType) {
        this.name = name;
        this.simpleType = simpleType;
    }

    public static List<ReturnsType> getExchangeValues() {
        return Arrays.stream(ReturnsType.values()).filter(returnsType -> returnsType.getSimpleType().equals("E")).collect(Collectors.toList());
    }

    public static List<ReturnsType> getReturnValues() {
        return Arrays.stream(ReturnsType.values()).filter(returnsType -> returnsType.getSimpleType().equals("R")).collect(Collectors.toList());
    }

    @JsonCreator
    public static ReturnsType from(String s) {
        try {
            return ReturnsType.valueOf(s.toUpperCase());
        } catch (IllegalArgumentException | NullPointerException e) {
            return null;
        }
    }
}
