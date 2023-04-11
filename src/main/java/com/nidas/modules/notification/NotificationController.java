package com.nidas.modules.notification;

import com.nidas.modules.account.Account;
import com.nidas.modules.account.CurrentAccount;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.ArrayList;
import java.util.List;

@Controller
@RequiredArgsConstructor
public class NotificationController {

    private final NotificationRepository notificationRepository;
    private final NotificationService notificationService;

    @GetMapping("/notifications")
    public String getNotifications(@CurrentAccount Account account, Model model) {
        List<Notification> notificationList = notificationRepository.findByAccountAndCheckedOrderByCreatedDateTimeDesc(account, false);
        long numberOfChecked = notificationRepository.countByAccountAndChecked(account, true);
        putCategorizedNotifications(notificationList, model, numberOfChecked, notificationList.size());
        model.addAttribute("isNew", true);
        return "notification/notification-list";
    }

    @GetMapping("/notifications/old")
    public String getOldNotifications(@CurrentAccount Account account, Model model) {
        List<Notification> notificationList = notificationRepository.findByAccountAndCheckedOrderByCreatedDateTimeDesc(account, true);
        long numberOfNotChecked = notificationRepository.countByAccountAndChecked(account, false);
        putCategorizedNotifications(notificationList, model, notificationList.size(), numberOfNotChecked);
        model.addAttribute("isNew", false);
        return "notification/notification-list";
    }

    @PostMapping("/notifications/read")
    public String readNotifications(@CurrentAccount Account account) {
        List<Notification> notificationList = notificationRepository.findByAccountAndCheckedOrderByCreatedDateTimeDesc(account, false);
        notificationService.readAll(notificationList);
        return "redirect:/notifications";
    }

    @PostMapping("/notifications/delete")
    public String deleteNotifications(@CurrentAccount Account account) {
        List<Notification> notificationList = notificationRepository.findByAccountAndCheckedOrderByCreatedDateTimeDesc(account, true);
        notificationService.deleteAll(notificationList);
        return "redirect:/notifications/old";
    }

    private void putCategorizedNotifications(List<Notification> notificationList, Model model,
                                             long numberOfChecked, long numberOfNotChecked) {
        List<Notification> accountNotificationList = new ArrayList<>();
        List<Notification> orderNotificationList = new ArrayList<>();
        List<Notification> qnaNotificationList = new ArrayList<>();

        for (Notification notification : notificationList) {
            switch (notification.getType()) {
                case ACCOUNT_GRADE_CHANGED: accountNotificationList.add(notification); break;
                case ORDER_STATUS_CHANGED: orderNotificationList.add(notification); break;
                case QNA_REPLY: qnaNotificationList.add(notification); break;
            }
        }
        model.addAttribute("numberOfChecked", numberOfChecked);
        model.addAttribute("numberOfNotChecked", numberOfNotChecked);
        model.addAttribute("notificationList", notificationList);
        model.addAttribute("accountNotificationList", accountNotificationList);
        model.addAttribute("orderNotificationList", orderNotificationList);
        model.addAttribute("qnaNotificationList", qnaNotificationList);
    }

}
