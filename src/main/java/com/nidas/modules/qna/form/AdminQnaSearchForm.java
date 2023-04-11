package com.nidas.modules.qna.form;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class AdminQnaSearchForm {

    private String email = "";

    private String productName = "";

    private String type = "";

    private boolean exceptReplied;

}
