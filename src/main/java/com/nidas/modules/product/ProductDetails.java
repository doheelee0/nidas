package com.nidas.modules.product;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Getter @Setter
public class ProductDetails {

    @Id @GeneratedValue
    private Long id;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private Color color;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private Size size;

    private Integer stock = 0;

    @ManyToOne(fetch = FetchType.LAZY)
    private Product product;

    public void subtractStock(int quantity) {
        int stock = this.stock - quantity;
        this.stock = stock > 0 ? stock : 0;
    }

}
