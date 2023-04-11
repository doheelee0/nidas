package com.nidas.modules.product.form;

import com.nidas.modules.product.Sorting;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class AdminProductSearchForm {

    private String keywords = "";

    private boolean discount;

    private boolean soldOut;

    private boolean recent;

    private String color = "";

    private Sorting sorting = Sorting.SALES;
}
