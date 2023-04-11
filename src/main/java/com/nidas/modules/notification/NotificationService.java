package com.nidas.modules.notification;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
@RequiredArgsConstructor
public class NotificationService {

    private final NotificationRepository notificationRepository;

    public void readAll(List<Notification> notificationList) {
        notificationList.forEach(notification -> notification.setChecked(true));
        notificationRepository.saveAll(notificationList);
    }

    public void deleteAll(List<Notification> notificationList) {
        notificationRepository.deleteAllInBatch(notificationList);
    }
}
