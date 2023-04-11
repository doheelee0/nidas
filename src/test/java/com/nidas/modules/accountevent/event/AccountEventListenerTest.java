package com.nidas.modules.accountevent.event;

import com.nidas.infra.AbstractContainerBaseTest;
import com.nidas.infra.config.MockMvcTest;
import com.nidas.infra.mail.EmailMessage;
import com.nidas.infra.mail.EmailService;
import com.nidas.modules.account.Account;
import com.nidas.modules.account.AccountRepository;
import com.nidas.modules.account.WithAccount;
import com.nidas.modules.accountevent.AccountEventService;
import com.nidas.modules.notification.NotificationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.core.task.SyncTaskExecutor;
import org.springframework.scheduling.annotation.AsyncConfigurer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@MockMvcTest
public class AccountEventListenerTest extends AbstractContainerBaseTest {

    @Autowired private AccountRepository accountRepository;
    @Autowired private NotificationRepository notificationRepository;
    @Autowired private AccountEventService accountEventService;
    @MockBean private EmailService emailService;
    @MockBean AsyncConfigurer asyncConfigurer;

    private final String TEST_EMAIL = "test@email.com";

    @BeforeEach
    public void setup() {
        when(asyncConfigurer.getAsyncExecutor()).thenReturn(new SyncTaskExecutor());
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("주문 후 유저의 멤버쉽 등급이 변경될 때 해당 유저에게 알림과 이메일을 보내는지 확인")
    @Test
    public void handleAccountGradeChangedEvent() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        account.setReceivingInfoByEmail(true);
        account.setReceivingInfoByWeb(true);
        accountRepository.flush();

        accountEventService.updateOrderInfo(account, 100000l, 1000l, 3);

        assertEquals(notificationRepository.countByAccountAndChecked(account, false), 1);
        verify(emailService, times(2)).sendEmail(any(EmailMessage.class));
    }

}
