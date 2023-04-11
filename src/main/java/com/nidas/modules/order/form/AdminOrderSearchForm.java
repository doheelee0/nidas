package com.nidas.modules.order.form;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class AdminOrderSearchForm {

    private String orderNumber = "";

    private String email = "";

    private String productName = "";

    private String orderStatus = "";

}
