package com.nidas.modules.accountevent.event;

import com.nidas.infra.config.AppProperties;
import com.nidas.infra.mail.EmailMessage;
import com.nidas.infra.mail.EmailService;
import com.nidas.modules.account.Account;
import com.nidas.modules.notification.Notification;
import com.nidas.modules.notification.NotificationRepository;
import com.nidas.modules.notification.NotificationType;
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
public class AccountEventListener {

    private final NotificationRepository notificationRepository;
    private final EmailService emailService;
    private final TemplateEngine templateEngine;
    private final AppProperties appProperties;

    @EventListener
    public void handleAccountGradeChangedEvent(AccountGradeChangedEvent accountGradeChangedEvent) {
        Account account = accountGradeChangedEvent.getAccount();
        String message = accountGradeChangedEvent.getMessage();
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
        notification.setLink("/mypage/membership");
        notification.setMessage(message);
        notification.setType(NotificationType.ACCOUNT_GRADE_CHANGED);
        notificationRepository.save(notification);
    }

    private void sendEmail(Account account, String contextMessage) {
        Context context = new Context();
        context.setVariable("name", account.getName());
        context.setVariable("link", "/mypage/membership");
        context.setVariable("linkName", "내 멤버쉽 확인하기");
        context.setVariable("message", contextMessage);
        context.setVariable("host", appProperties.getHost());
        String message = templateEngine.process("mail/simple-link", context);

        EmailMessage emailMessage = EmailMessage.builder()
                .to(account.getEmail())
                .subject("Nidas - 멤버쉽 등급 변경")
                .message(message)
                .build();
        emailService.sendEmail(emailMessage);
    }
}
