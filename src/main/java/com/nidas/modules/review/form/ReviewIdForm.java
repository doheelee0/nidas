package com.nidas.modules.review.form;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotNull;

@Setter @Getter
public class ReviewIdForm {

    @NotNull(message = "해당하는 리뷰가 존재하지 않습니다.")
    private Long reviewId;

    @NotNull(message = "존재하지 않는 회원입니다.")
    private Long accountId;

}
