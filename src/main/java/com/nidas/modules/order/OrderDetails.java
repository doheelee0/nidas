package com.nidas.modules.order;

import com.nidas.modules.product.ProductDetails;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.List;

@NamedEntityGraph(
        name = "OrderDetails.withOrderAndAccount",
        attributeNodes = @NamedAttributeNode(value = "order", subgraph = "account"),
        subgraphs = @NamedSubgraph(name = "account", attributeNodes = @NamedAttributeNode("account"))
)

@NamedEntityGraph(
        name = "OrderDetails.withOrderAndProductAndProductDetails",
        attributeNodes = {
                @NamedAttributeNode("order"),
                @NamedAttributeNode(value = "productDetails", subgraph = "product")
        },
        subgraphs = @NamedSubgraph(name = "product", attributeNodes = @NamedAttributeNode("product"))
)

@NamedEntityGraph(
        name = "OrderDetails.withOrderAndAccountAndProductAndProductDetails",
        attributeNodes = {
                @NamedAttributeNode(value = "order", subgraph = "account"),
                @NamedAttributeNode(value = "productDetails", subgraph = "product")
        },
        subgraphs = {
                @NamedSubgraph(name = "account", attributeNodes = @NamedAttributeNode("account")),
                @NamedSubgraph(name = "product", attributeNodes = @NamedAttributeNode("product"))
        }
)

@Entity
@Getter @Setter @EqualsAndHashCode(of = "id")
public class OrderDetails {

    @Id @GeneratedValue
    private Long id;

    @Column(nullable = false)
    private Integer unitPrice;

    @Column(nullable = false)
    private Integer quantity;

    @Enumerated(EnumType.STRING)
    private OrderStatus status;

    @ManyToOne(fetch = FetchType.LAZY)
    private Order order;

    @ManyToOne(fetch = FetchType.LAZY)
    private ProductDetails productDetails;

    private boolean reviewed;

    public boolean canCancel() {
        return this.status == OrderStatus.PAID;
    }

    public boolean canReview() {
        return List.of(OrderStatus.DELIVERED, OrderStatus.EXCHANGING, OrderStatus.EXCHANGED).contains(this.status)
                && this.order.getCreatedDateTime().isAfter(LocalDateTime.now().minusMonths(3))
                && !this.reviewed;
    }

    public boolean canReturns() {
        return this.status == OrderStatus.DELIVERED
                && this.order.getArrivalDateTime().isAfter(LocalDateTime.now().minusDays(7));
    }
}
