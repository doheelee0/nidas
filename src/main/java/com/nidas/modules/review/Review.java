package com.nidas.modules.review;

import com.nidas.modules.account.Account;
import com.nidas.modules.order.OrderDetails;
import com.nidas.modules.product.Product;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.time.LocalDateTime;

@NamedEntityGraph(
        name = "Review.withProductAndOrderDetailsAndProductDetailsAndOrder",
        attributeNodes = {
                @NamedAttributeNode(value = "product"),
                @NamedAttributeNode(value = "orderDetails", subgraph = "productDetailsAndOrder")
        },
        subgraphs = {
                @NamedSubgraph(name = "productDetailsAndOrder", attributeNodes = {
                        @NamedAttributeNode("productDetails"),
                        @NamedAttributeNode("order")
                }),
        }
)

@NamedEntityGraph(
        name = "Review.withAll",
        attributeNodes = {
                @NamedAttributeNode(value = "account"),
                @NamedAttributeNode(value = "product"),
                @NamedAttributeNode(value = "orderDetails")
        }
)

@NamedEntityGraph(
        name = "Review.withProduct",
        attributeNodes = @NamedAttributeNode(value = "product")
)

@Entity
@Getter @Setter @EqualsAndHashCode(of = "id")
public class Review {

    @Id @GeneratedValue
    private Long id;

    @Column(nullable = false)
    private Integer rank;

    @Column(nullable = false)
    private String content;

    @Lob
    private String image;

    private Integer earnedMileage;

    private LocalDateTime createdDateTime;

    private LocalDateTime updatedDateTime;

    private boolean deleted;

    @ManyToOne(fetch = FetchType.LAZY)
    private Account account;

    @ManyToOne(fetch = FetchType.LAZY)
    private Product product;

    @OneToOne(fetch = FetchType.LAZY)
    private OrderDetails orderDetails;

    public void setCalculatedEarnedMileage(int price, int quantity) {
        if (this.image != null) { // 포토리뷰
            this.earnedMileage = (int) (0.01 * price * quantity);
        } else {
            this.earnedMileage = (int) (0.005 * price * quantity);
        }
    }

    public boolean isEditable() {
        return this.createdDateTime.isAfter(LocalDateTime.now().minusMonths(3));
    }
}
