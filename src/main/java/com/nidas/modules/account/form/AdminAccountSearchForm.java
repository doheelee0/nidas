package com.nidas.modules.account.form;

import com.nidas.modules.account.Sorting;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class AdminAccountSearchForm {

    private String keywords = "";

    private String gender;

    private boolean birthdayOnToday;

    private boolean emailVerified;

    private String membership;

    private boolean notDeleted;

    private Sorting sorting = Sorting.EMAIL;
}
