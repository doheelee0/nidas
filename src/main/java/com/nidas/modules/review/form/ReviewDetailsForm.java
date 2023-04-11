package com.nidas.modules.review.form;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.nidas.modules.product.ProductDetails;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter @Setter
public class ReviewDetailsForm {

    private Long id;

    private Integer rank;

    private String content;

    private String image;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy.MM.dd")
    private LocalDateTime createdDateTime;

    private String email;

    private String color;

    private Integer size;

    public void setProductDetails(ProductDetails productDetails) {
        this.color = productDetails.getColor().name();
        this.size = productDetails.getSize().getValue();
    }

}
