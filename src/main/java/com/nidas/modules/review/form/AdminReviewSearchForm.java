package com.nidas.modules.review.form;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class AdminReviewSearchForm {

    private String email = "";

    private String productName = "";

    private boolean exceptDeleted;

}
