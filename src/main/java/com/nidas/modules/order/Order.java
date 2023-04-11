package com.nidas.modules.order;

import com.nidas.modules.account.Account;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@NamedEntityGraph(
        name = "Order.withOrderDetailsAndProductDetailsAndProduct",
        attributeNodes = @NamedAttributeNode(value = "orderDetails", subgraph = "productDetails"),
        subgraphs = {
                @NamedSubgraph(
                        name = "productDetails",
                        attributeNodes = @NamedAttributeNode(value = "productDetails", subgraph = "product")
                ),
                @NamedSubgraph(name = "product", attributeNodes = @NamedAttributeNode("product"))
        }
)

@Entity
@Table(name = "orders")
@Getter @Setter @EqualsAndHashCode(of = "id")
public class Order {

    @Id @GeneratedValue
    private Long id;

    @Column(nullable = false, unique = true, length = 16)
    private String orderNumber;

    @Column(nullable = false, length = 50)
    private String receiver;

    @Column(nullable = false, length = 11)
    private String phoneNumber;

    @Column(nullable = false, length = 5)
    private String address1;

    @Column(nullable = false)
    private String address2;

    private String address3;

    private String deliveryRequest;

    @Column(nullable = false)
    private Integer deliveryPrice;

    private Long mileageUsage = 0L;

    @Column(nullable = false)
    private Long totalPrice;

    private LocalDateTime createdDateTime;

    private LocalDateTime arrivalDateTime;

    @ManyToOne(fetch = FetchType.LAZY)
    private Account account;

    @OneToMany(mappedBy = "order", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<OrderDetails> orderDetails = new ArrayList<>();

    public void addOrderDetails(OrderDetails orderDetails) {
        this.orderDetails.add(orderDetails);
        orderDetails.setOrder(this);
    }

}
