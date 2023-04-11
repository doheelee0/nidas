package com.nidas.modules.order.form;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class AdminOrderDetailsInfo {

    private String thumbnail;

    private String name;

    private String color;

    private Integer size;

    private Integer quantity;

    private String status;

    private boolean reviewed;

}
