package com.nidas.modules.order;

import com.nidas.modules.account.Account;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Transactional(readOnly = true)
public interface OrderDetailsRepository extends JpaRepository<OrderDetails, Long> {

    @EntityGraph("OrderDetails.withOrderAndAccount")
    OrderDetails findOrderDetailsWithOrderAndAccountByIdAndOrder_Account(Long id, Account account);

    @EntityGraph("OrderDetails.withOrderAndAccountAndProductAndProductDetails")
    OrderDetails findByIdAndOrder_Account(Long id, Account account);

    @EntityGraph("OrderDetails.withOrderAndProductAndProductDetails")
    List<OrderDetails> findByOrder_AccountAndStatusInOrderByOrder_CreatedDateTimeDesc(Account account, List<OrderStatus> statusList);

    @EntityGraph("OrderDetails.withOrderAndProductAndProductDetails")
    List<OrderDetails> findByOrder_Account(Account account);

}
