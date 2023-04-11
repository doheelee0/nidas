package com.nidas.modules.review.form;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.nidas.modules.product.Product;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter @Setter
public class AdminReviewInfo {

    private String productName;

    private String productThumbnail;

    private Integer rank;

    private String content;

    private String image;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy.MM.dd")
    private LocalDateTime createdDateTime;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy.MM.dd")
    private LocalDateTime updatedDateTime;

    private boolean deleted;

    public void setProduct(Product product) {
        this.productName = product.getName();
        this.productThumbnail = product.getThumbnail();
    }
}
