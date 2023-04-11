package com.nidas.modules.order.form;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import java.util.Set;

@Getter @Setter
public class OrderForm {

    @NotBlank(message = "수령인을 입력해주세요.")
    @Pattern(
            regexp = "^([a-zA-Z가-힣]{1,50})$",
            message = "수령인을 영문자, 한글로 입력해주세요."
    )
    private String receiver;

    @NotBlank(message = "우편번호를 입력해주세요.")
    private String address1;

    @NotBlank(message = "주소를 입력해주세요.")
    private String address2;

    private String address3;

    @NotBlank(message = "전화번호를 입력해주세요.")
    @Pattern(
            regexp = "^(01[016789])([0-9]{3,4})([0-9]{4})$",
            message = "(-) 없이 휴대폰번호 10자리 또는 11자리를 입력해주세요."
    )
    private String phoneNumber;

    private String deliveryRequest;

    @NotNull(message = "사용하는 마일리지 값이 없습니다.")
    private Long mileageUsage;

    @NotEmpty(message = "주문하려는 상품이 없습니다.")
    private Set<Long> cartIdList;

}
