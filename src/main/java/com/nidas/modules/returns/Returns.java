package com.nidas.modules.returns;

import com.nidas.modules.account.Account;
import com.nidas.modules.order.OrderDetails;
import com.nidas.modules.order.OrderStatus;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.time.LocalDateTime;

@NamedEntityGraph(
        name = "Returns.withOrderDetailsAndOrder",
        attributeNodes = @NamedAttributeNode(value = "orderDetails", subgraph = "order"),
        subgraphs = @NamedSubgraph(name = "order", attributeNodes = @NamedAttributeNode("order"))
)

@NamedEntityGraph(
        name = "Returns.withOrderDetailsAndOrderAndProductDetailsAndProduct",
        attributeNodes = @NamedAttributeNode(value = "orderDetails", subgraph = "productDetailsAndOrder"),
        subgraphs = {
                @NamedSubgraph(
                        name = "productDetailsAndOrder",
                        attributeNodes = {
                                @NamedAttributeNode("order"),
                                @NamedAttributeNode(value = "productDetails", subgraph = "product")
                        }
                ),
                @NamedSubgraph(name = "product", attributeNodes = @NamedAttributeNode("product"))
        }
)

@Entity
@Getter @Setter @EqualsAndHashCode(of = "id")
public class Returns {

    @Id @GeneratedValue
    private Long id;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private ReturnsType type;

    @Column(nullable = false)
    private String content;

    @Lob
    private String image;

    private LocalDateTime createdDateTime;

    private LocalDateTime completedDateTime;

    @ManyToOne(fetch = FetchType.LAZY)
    private Account account;

    @OneToOne(fetch = FetchType.LAZY)
    private OrderDetails orderDetails;

    public boolean isNotCompleted() {
        OrderStatus status = this.orderDetails.getStatus();
        return this.completedDateTime == null && (status == OrderStatus.EXCHANGING || status == OrderStatus.RETURNING);
    }
}
