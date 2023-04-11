package com.nidas.modules.product;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Getter @Setter
public class ProductImage {

    @Id @GeneratedValue
    private Long id;

    @Lob
    @Column(nullable = false)
    private String image;

    @ManyToOne
    private Product product;

}
