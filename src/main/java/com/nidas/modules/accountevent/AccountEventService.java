package com.nidas.modules.accountevent;

import com.nidas.modules.account.Account;
import com.nidas.modules.account.AccountRepository;
import com.nidas.modules.account.Membership;
import com.nidas.modules.accountevent.event.AccountGradeChangedEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class AccountEventService {

    private final ApplicationEventPublisher eventPublisher;
    private final AccountRepository accountRepository;

    public void updateOrderInfo(Account account, Long totalPrice, Long mileageUsage, int numberOfOrder) {
        Long totalPaymentToUpdate = account.getTotalPayment() + totalPrice;
        Membership membership = account.getMembership();
        Membership membershipToUpdate = Membership.getEnumByBound(totalPaymentToUpdate);

        account.setMileage(account.getMileage() - mileageUsage);
        account.setTotalOrder(account.getTotalOrder() + numberOfOrder);
        account.setTotalPayment(totalPaymentToUpdate);
        account.setMembership(membershipToUpdate);
        accountRepository.save(account);
        if (membership != membershipToUpdate) {
            eventPublisher.publishEvent(new AccountGradeChangedEvent(account));
        }
    }

}
