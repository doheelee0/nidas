package com.nidas.modules.review.form;

import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.Length;

import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Getter @Setter
public class ReviewForm {

    @NotNull(message = "평점을 선택해주세요.")
    @Min(value = 1, message = "평점은 최소 1점이상이어야 합니다.")
    @Max(value = 5, message = "평점은 최대 5점까지 줄 수 있습니다.")
    private Integer rank;

    @NotBlank(message = "리뷰 내용을 입력해주세요.")
    @Length(min = 10, message = "리뷰 내용을 최소 10자 이상 작성해주세요.")
    private String content;

    private String image;

}
