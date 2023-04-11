package com.nidas.modules.accountevent.event;

import com.nidas.modules.account.Account;
import lombok.Getter;

@Getter
public class AccountGradeChangedEvent {

    private Account account;

    private String message;

    public AccountGradeChangedEvent(Account account) {
        this.account = account;
        this.message = "고객님의 멤버쉽 등급이 " + account.getMembership() + "로 변경되셨습니다.";
    }
}
