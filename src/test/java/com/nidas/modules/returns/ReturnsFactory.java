package com.nidas.modules.returns;

import com.nidas.modules.account.Account;
import com.nidas.modules.order.OrderDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
public class ReturnsFactory {

    @Autowired private ReturnsRepository returnsRepository;

    public Returns createReturns(Account account, OrderDetails orderDetails) {
        Returns returns = new Returns();
        returns.setType(ReturnsType.EXCHANGE_DELIVERED_BROKEN);
        returns.setContent("test");
        returns.setCreatedDateTime(LocalDateTime.now());
        returns.setAccount(account);
        returns.setOrderDetails(orderDetails);
        return returnsRepository.save(returns);
    }

}
