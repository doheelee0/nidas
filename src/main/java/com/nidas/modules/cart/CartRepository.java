package com.nidas.modules.cart;

import com.nidas.modules.account.Account;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;

@Transactional(readOnly = true)
public interface CartRepository extends JpaRepository<Cart, Long> {

    @EntityGraph("Cart.withProductDetails")
    List<Cart> findCartWithProductDetailsByAccount(Account account);

    @EntityGraph("Cart.withProductDetailsAndProduct")
    List<Cart> findCartWithProductDetailsAndProductByAccount(Account account);

    Cart findByIdAndAccount(Long id, Account account);

    List<Cart> findByIdInAndAccount(Set<Long> idList, Account account);

    @EntityGraph("Cart.withProductDetailsAndProduct")
    List<Cart> findCartWithProductDetailsAndProductByIdInAndAccount(Set<Long> idList, Account account);

    @EntityGraph("Cart.withProductDetailsAndProduct")
    List<Cart> findCartWithProductDetailsAndProductByAccountAndOrderCheckTrue(Account account);

}
