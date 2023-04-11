package com.nidas.modules.favorites;

import com.nidas.modules.account.Account;
import com.nidas.modules.product.Product;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Transactional(readOnly = true)
public interface FavoritesRepository extends JpaRepository<Favorites, Long> {

    boolean existsByAccountAndProduct(Account account, Product product);

    long countByAccount(Account account);

    Favorites findByAccountAndProduct(Account account, Product product);

    @EntityGraph("Favorites.withProduct")
    List<Favorites> findFavoritesWithProductByAccount(Account account);

}
