package com.nidas.modules.product.form;

import com.nidas.modules.product.MainCategory;
import com.nidas.modules.product.SubCategory;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.Length;

import javax.validation.Valid;
import javax.validation.constraints.*;
import java.util.ArrayList;
import java.util.List;

@Getter @Setter
public class ProductForm {

    @NotNull(message = "잘못된 카테고리 값입니다.")
    private MainCategory mainCategory;

    @NotNull(message = "잘못된 카테고리 값입니다.")
    private SubCategory subCategory;

    @NotBlank(message = "상품명을 입력해주세요.")
    private String name;

    @NotNull(message = "가격을 입력해주세요.")
    @Min(value = 0, message = "0원 이상이여야 합니다.")
    private Integer price;

    @NotNull(message = "할인가를 입력해주세요.")
    @Min(value = 0, message = "할인가는 0이상의 값이어야 합니다.")
    @Max(value = 100, message = "할인가는 100이하의 값이어야 합니다.")
    private Integer discountRate;

    @NotNull(message = "재료를 입력해주세요.")
    @Length(max = 50, message = "50자 이하로 입력해주세요.")
    private String material;

    @NotNull(message = "생산지를 입력해주세요.")
    @Length(max = 50, message = "50자 이하로 입력해주세요.")
    private String madeIn;

    @NotNull(message = "세탁법을 입력해주세요.")
    private String washing;

    @NotNull(message = "설명을 입력해주세요.")
    private String description;

    @Size(max = 10, message = "최대 10개까지 상품 이미지를 첨부할 수 있습니다.")
    @Valid
    private List<ProductImageForm> images = new ArrayList<>();

    @Valid
    private List<ProductDetailsForm> details = new ArrayList<>();

    public String getThumbnail() {
        if (this.images.size() == 0) return null;
        return this.images.get(0).getImage(); // 첫 번째 사진을 썸네일로 사용
    }

}
