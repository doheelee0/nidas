package com.nidas.modules.product;

import com.nidas.infra.exception.ResourceNotFoundException;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@NamedEntityGraph(name = "Product.withImagesAndDetails", attributeNodes = {
        @NamedAttributeNode("images"),
        @NamedAttributeNode("details")
})

@Entity
@Getter @Setter @EqualsAndHashCode(of = "id")
public class Product {

    @Id @GeneratedValue
    private Long id;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private MainCategory mainCategory;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private SubCategory subCategory;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false, length = 50)
    private String material;

    @Column(nullable = false, length = 50)
    private String madeIn;

    @Column(nullable = false)
    private String washing;

    @Column(nullable = false)
    private Integer price;

    private Integer discountRate = 0;

    @Lob
    @Column(nullable = false)
    private String description;

    @Lob
    private String thumbnail;

    private LocalDateTime createdDateTime = LocalDateTime.now();

    private LocalDateTime updatedDateTime;

    private Integer entireSalesQuantity = 0;

    private Long entireSalesAmount = 0L;

    private Double rank = 0.0;

    private Integer reviewCount = 0;

    private Integer favoritesCount = 0;

    private boolean deleted;

    @OneToMany(mappedBy = "product", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy(value = "id asc")
    private Set<ProductImage> images = new LinkedHashSet<>();

    @OneToMany(mappedBy = "product", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy(value = "id asc")
    private Set<ProductDetails> details = new LinkedHashSet<>();

    public void setImages(List<ProductImage> images) {
        images.forEach(image -> image.setProduct(this));
        this.images.addAll(images);
    }

    public void setDetails(List<ProductDetails> productDetails) {
        productDetails.forEach(details -> details.setProduct(this));
        this.details.addAll(productDetails);
    }

    public void removeAllImages() {
        this.images.forEach(image -> image.setProduct(null));
        this.images.clear();
    }

    public void removeAllDetails() {
        this.details.forEach(d -> d.setProduct(null));
        this.details.clear();
    }

    public ProductDetails getProductDetails(Color color, Size size) {
        for (ProductDetails pd : this.details) {
            if (pd.getColor() == color && pd.getSize() == size) {
                return pd;
            }
        }
        throw new ResourceNotFoundException("존재하지 않는 물품입니다.");
    }

    public int getDiscountedPrice() {
        return (int) Math.round((this.price * ((100 - this.discountRate) / 100.0)) / 10) * 10;
    }

    public void setSales(int price, int quantity) {
        this.entireSalesQuantity += quantity;
        this.entireSalesAmount += ((long) price * quantity);
    }
}
