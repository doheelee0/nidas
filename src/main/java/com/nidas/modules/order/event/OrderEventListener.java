package com.nidas.modules.order.event;

import com.nidas.infra.config.AppProperties;
import com.nidas.infra.mail.EmailMessage;
import com.nidas.infra.mail.EmailService;
import com.nidas.modules.account.Account;
import com.nidas.modules.notification.Notification;
import com.nidas.modules.notification.NotificationRepository;
import com.nidas.modules.notification.NotificationType;
import com.nidas.modules.order.Order;
import com.nidas.modules.order.OrderDetails;
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
public class OrderEventListener {

    private final NotificationRepository notificationRepository;
    private final EmailService emailService;
    private final TemplateEngine templateEngine;
    private final AppProperties appProperties;

    @EventListener
    public void handleOrderStatusChangedEvent(OrderStatusChangedEvent orderStatusChangedEvent) {
        OrderDetails orderDetails = orderStatusChangedEvent.getOrderDetails();
        Order order = orderDetails.getOrder();
        Account account = order.getAccount();
        String message = orderStatusChangedEvent.getMessage();
        if (account.isReceivingInfoByWeb()) {
            createNewNotification(order, account, message);
        }
        if (account.isReceivingInfoByEmail()) {
            sendEmail(order, account, message);
        }
    }

    private void createNewNotification(Order order, Account account, String message) {
        Notification notification = new Notification();
        notification.setAccount(account);
        notification.setChecked(false);
        notification.setCreatedDateTime(LocalDateTime.now());
        notification.setLink("/mypage/order/" + order.getOrderNumber());
        notification.setMessage(message);
        notification.setType(NotificationType.ORDER_STATUS_CHANGED);
        notificationRepository.save(notification);
    }

    private void sendEmail(Order order, Account account, String contextMessage) {
        Context context = new Context();
        context.setVariable("name", account.getName());
        context.setVariable("link", "/mypage/order/" + order.getOrderNumber());
        context.setVariable("linkName", "주문상태 확인하기");
        context.setVariable("message", contextMessage);
        context.setVariable("host", appProperties.getHost());
        String message = templateEngine.process("mail/simple-link", context);

        EmailMessage emailMessage = EmailMessage.builder()
                .to(account.getEmail())
                .subject("Nidas - 주문상태 변경")
                .message(message)
                .build();
        emailService.sendEmail(emailMessage);
    }
}
