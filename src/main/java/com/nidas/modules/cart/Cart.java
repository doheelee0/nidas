package com.nidas.modules.cart;

import com.nidas.modules.account.Account;
import com.nidas.modules.product.ProductDetails;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.time.LocalDateTime;

@NamedEntityGraph(
        name = "Cart.withProductDetails",
        attributeNodes = @NamedAttributeNode(value = "productDetails")
)

@NamedEntityGraph(
        name = "Cart.withProductDetailsAndProduct",
        attributeNodes = @NamedAttributeNode(value = "productDetails", subgraph = "product"),
        subgraphs = @NamedSubgraph(name = "product", attributeNodes = @NamedAttributeNode("product"))
)

@Entity
@Getter @Setter @EqualsAndHashCode(of = "id")
public class Cart {

    @Id @GeneratedValue
    private Long id;

    @Column(nullable = false)
    private Integer quantity;

    private LocalDateTime createdDateTime;

    private boolean orderCheck; // 현재 주문중인 아이템인지 아닌지 확인

    @ManyToOne(fetch = FetchType.LAZY)
    private Account account;

    @ManyToOne(fetch = FetchType.LAZY)
    private ProductDetails productDetails;

    public boolean canOrder() {
        return this.orderCheck && this.quantity <= this.getProductDetails().getStock();
    }

}
