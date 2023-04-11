package com.nidas.modules.product.form;

import com.nidas.modules.product.MainCategory;
import com.nidas.modules.product.Sorting;
import com.nidas.modules.product.SubCategory;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class ProductSearchForm {

    private String keywords = "";

    private MainCategory mainCategory;

    private SubCategory subCategory;

    private boolean discount;

    private boolean exceptSoldOut;

    private boolean recent;

    private Integer minPrice = 0;

    private Integer maxPrice = Integer.MAX_VALUE;

    private String color = "";

    private Sorting sorting = Sorting.SALES;

}
