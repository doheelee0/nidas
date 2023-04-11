package com.nidas.modules.returns.form;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class AdminReturnsSearchForm {

    private String orderNumber = "";

    private String email = "";

    private String productName = "";

    private String returnsStatus = "";

}
