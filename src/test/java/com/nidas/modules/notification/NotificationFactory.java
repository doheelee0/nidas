package com.nidas.modules.notification;

import com.nidas.modules.account.Account;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
public class NotificationFactory {

    @Autowired private NotificationRepository notificationRepository;

    public Notification createNotification(Account account, NotificationType type) {
        Notification notification = new Notification();
        notification.setLink("test");
        notification.setType(type);
        notification.setMessage("test");
        notification.setCreatedDateTime(LocalDateTime.now());
        notification.setAccount(account);
        return notificationRepository.save(notification);
    }

}
