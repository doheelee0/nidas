package com.nidas.modules.favorites;

import com.nidas.modules.account.Account;
import com.nidas.modules.product.Product;
import lombok.*;

import javax.persistence.*;

@NamedEntityGraph(name = "Favorites.withProduct", attributeNodes = {
        @NamedAttributeNode("product")
})

@Entity
@Getter @Setter @EqualsAndHashCode(of = "id")
@Builder @NoArgsConstructor @AllArgsConstructor
public class Favorites {

    @Id @GeneratedValue
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    private Account account;

    @ManyToOne(fetch = FetchType.LAZY)
    private Product product;

}
