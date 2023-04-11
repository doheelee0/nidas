package com.nidas.modules.qna.event;

import com.nidas.infra.config.AppProperties;
import com.nidas.infra.mail.EmailMessage;
import com.nidas.infra.mail.EmailService;
import com.nidas.modules.account.Account;
import com.nidas.modules.notification.Notification;
import com.nidas.modules.notification.NotificationRepository;
import com.nidas.modules.notification.NotificationType;
import com.nidas.modules.qna.Qna;
import lombok.RequiredArgsConstructor;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.time.LocalDateTime;

@Async
@Component
@Transactional
@RequiredArgsConstructor
public class QnaEventListener {

    private final NotificationRepository notificationRepository;
    private final EmailService emailService;
    private final TemplateEngine templateEngine;
    private final AppProperties appProperties;

    @EventListener
    public void handleQnaReplyEvent(QnaReplyEvent qnaReplyEvent) {
        Qna qna = qnaReplyEvent.getQna();
        Account account = qna.getAccount();
        String message = qnaReplyEvent.getMessage();
        if (account.isReceivingInfoByWeb()) {
            createNewNotification(account, message);
        }
        if (account.isReceivingInfoByEmail()) {
            sendEmail(account, message);
        }
    }

    private void createNewNotification(Account account, String message) {
        Notification notification = new Notification();
        notification.setAccount(account);
        notification.setChecked(false);
        notification.setCreatedDateTime(LocalDateTime.now());
        notification.setLink("/mypage/qna-list");
        notification.setMessage(message);
        notification.setType(NotificationType.QNA_REPLY);
        notificationRepository.save(notification);
    }

    private void sendEmail(Account account, String contextMessage) {
        Context context = new Context();
        context.setVariable("name", account.getName());
        context.setVariable("link", "/mypage/qna-list");
        context.setVariable("linkName", "답변 확인하러 가기");
        context.setVariable("message", contextMessage);
        context.setVariable("host", appProperties.getHost());
        String message = templateEngine.process("mail/simple-link", context);

        EmailMessage emailMessage = EmailMessage.builder()
                .to(account.getEmail())
                .subject("Nidas - Q&A 답변 완료")
                .message(message)
                .build();
        emailService.sendEmail(emailMessage);
    }
}
