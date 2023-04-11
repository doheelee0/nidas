package com.nidas.modules.qna.event;

import com.nidas.infra.AbstractContainerBaseTest;
import com.nidas.infra.config.MockMvcTest;
import com.nidas.infra.mail.EmailMessage;
import com.nidas.infra.mail.EmailService;
import com.nidas.modules.account.Account;
import com.nidas.modules.account.AccountRepository;
import com.nidas.modules.account.WithAccount;
import com.nidas.modules.notification.NotificationRepository;
import com.nidas.modules.product.Product;
import com.nidas.modules.product.ProductFactory;
import com.nidas.modules.qna.Qna;
import com.nidas.modules.qna.QnaFactory;
import com.nidas.modules.qna.QnaService;
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
public class QnaEventListenerTest extends AbstractContainerBaseTest {

    @Autowired private AccountRepository accountRepository;
    @Autowired private NotificationRepository notificationRepository;
    @Autowired private QnaService qnaService;
    @Autowired private ProductFactory productFactory;
    @Autowired private QnaFactory qnaFactory;
    @MockBean private EmailService emailService;
    @MockBean AsyncConfigurer asyncConfigurer;

    private final String TEST_EMAIL = "test@email.com";

    @BeforeEach
    public void setup() {
        when(asyncConfigurer.getAsyncExecutor()).thenReturn(new SyncTaskExecutor());
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("Q&A 답변이 처리되었을 때 해당 유저에게 알림과 이메일을 보내는지 확인")
    @Test
    public void handleOrderStatusChangedEvent() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        account.setReceivingInfoByEmail(true);
        account.setReceivingInfoByWeb(true);
        accountRepository.flush();

        Product product = productFactory.createProduct();
        Qna qna = qnaFactory.createQna(account, product);

        // 답변이 처음 달렸을때
        qnaService.replyQna(qna, "답변내용 테스트");

        assertEquals(notificationRepository.countByAccountAndChecked(account, false), 1);
        verify(emailService, times(2)).sendEmail(any(EmailMessage.class));

        // 답변이 수정되었을때
        qnaService.updateReply(qna, "답변내용 수정 테스트");

        assertEquals(notificationRepository.countByAccountAndChecked(account, false), 2);
        verify(emailService, times(3)).sendEmail(any(EmailMessage.class));
    }

}
