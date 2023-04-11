package com.nidas.modules.order;

import com.nidas.modules.account.Account;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Transactional(readOnly = true)
public interface OrderRepository extends JpaRepository<Order, Long>, OrderRepositoryExtension {

    @EntityGraph("Order.withOrderDetailsAndProductDetailsAndProduct")
    Order findByOrderNumberAndAccount(String orderNumber, Account account);

    @EntityGraph("Order.withOrderDetailsAndProductDetailsAndProduct")
    List<Order> findByAccount(Account account);

}
