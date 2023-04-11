package com.nidas.modules.account;

import com.nidas.infra.config.TestProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Component
public class AccountFactory {

    @Autowired private AccountRepository accountRepository;
    @Autowired private TestProperties testProperties;

    public Account createAccount(String email) {
        Account account = Account.builder()
                .email(email)
                .password(testProperties.getPassword())
                .passwordFindTokenGeneratedDateTime(LocalDateTime.now().minusHours(2))
                .name(testProperties.getName())
                .gender(Gender.valueOf(testProperties.getGender()))
                .birthday(LocalDate.parse(testProperties.getBirthday(), DateTimeFormatter.ofPattern("yyyy-MM-dd")))
                .phoneNumber(testProperties.getPhoneNumber())
                .totalPayment(0L)
                .totalOrder(0)
                .mileage(0L)
                .membership(Membership.BRONZE)
                .authority(Authority.ROLE_USER)
                .receivingInfoByWeb(true)
                .build();
        account.generateEmailCheckToken();
        return accountRepository.save(account);
    }

}
