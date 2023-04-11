package com.nidas.modules.notification;

import com.nidas.infra.AbstractContainerBaseTest;
import com.nidas.infra.config.MockMvcTest;
import com.nidas.modules.account.Account;
import com.nidas.modules.account.AccountRepository;
import com.nidas.modules.account.WithAccount;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@MockMvcTest
public class NotificationControllerTest extends AbstractContainerBaseTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private AccountRepository accountRepository;
    @Autowired private NotificationRepository notificationRepository;
    @Autowired private NotificationFactory notificationFactory;

    private final String TEST_EMAIL = "test@email.com";

    @WithAccount(TEST_EMAIL)
    @DisplayName("읽지 않은 알림 목록 화면 보이는지 테스트")
    @Test
    public void getNotifications() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        List<Notification> notificationList = new ArrayList<>();
        List<Notification> accountNotificationList = new ArrayList<>();
        List<Notification> orderNotificationList = new ArrayList<>();
        List<Notification> qnaNotificationList = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            accountNotificationList.add(notificationFactory.createNotification(account, NotificationType.ACCOUNT_GRADE_CHANGED));
            orderNotificationList.add(notificationFactory.createNotification(account, NotificationType.ORDER_STATUS_CHANGED));
            qnaNotificationList.add(notificationFactory.createNotification(account, NotificationType.QNA_REPLY));
        }
        notificationList.addAll(accountNotificationList);
        notificationList.addAll(orderNotificationList);
        notificationList.addAll(qnaNotificationList);

        Map<String, Object> model = mockMvc.perform(get("/notifications"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("notification/notification-list"))
                .andExpect(model().attributeExists("isNew", "numberOfChecked", "numberOfNotChecked",
                        "notificationList", "accountNotificationList", "orderNotificationList", "qnaNotificationList"))
                .andExpect(model().attribute("isNew", true))
                .andExpect(model().attribute("numberOfChecked", 0l))
                .andExpect(model().attribute("numberOfNotChecked", (long) notificationList.size()))
                .andExpect(authenticated().withUsername(TEST_EMAIL))
                .andReturn().getModelAndView().getModel();

        assertTrue(notificationList.containsAll((List<Notification>) model.get("notificationList")));
        assertTrue(accountNotificationList.containsAll((List<Notification>) model.get("accountNotificationList")));
        assertTrue(orderNotificationList.containsAll((List<Notification>) model.get("orderNotificationList")));
        assertTrue(qnaNotificationList.containsAll((List<Notification>) model.get("qnaNotificationList")));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("읽은 알림 목록 화면 보이는지 테스트")
    @Test
    public void getOldNotifications() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        List<Notification> notificationList = new ArrayList<>();
        List<Notification> accountNotificationList = new ArrayList<>();
        List<Notification> orderNotificationList = new ArrayList<>();
        List<Notification> qnaNotificationList = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            accountNotificationList.add(notificationFactory.createNotification(account, NotificationType.ACCOUNT_GRADE_CHANGED));
            orderNotificationList.add(notificationFactory.createNotification(account, NotificationType.ORDER_STATUS_CHANGED));
            qnaNotificationList.add(notificationFactory.createNotification(account, NotificationType.QNA_REPLY));
        }
        notificationList.addAll(accountNotificationList);
        notificationList.addAll(orderNotificationList);
        notificationList.addAll(qnaNotificationList);
        notificationList.forEach(notification -> notification.setChecked(true));

        Map<String, Object> model = mockMvc.perform(get("/notifications/old"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("notification/notification-list"))
                .andExpect(model().attributeExists("isNew", "numberOfChecked", "numberOfNotChecked",
                        "notificationList", "accountNotificationList", "orderNotificationList", "qnaNotificationList"))
                .andExpect(model().attribute("isNew", false))
                .andExpect(model().attribute("numberOfChecked", (long) notificationList.size()))
                .andExpect(model().attribute("numberOfNotChecked", 0l))
                .andExpect(authenticated().withUsername(TEST_EMAIL))
                .andReturn().getModelAndView().getModel();

        assertTrue(notificationList.containsAll((List<Notification>) model.get("notificationList")));
        assertTrue(accountNotificationList.containsAll((List<Notification>) model.get("accountNotificationList")));
        assertTrue(orderNotificationList.containsAll((List<Notification>) model.get("orderNotificationList")));
        assertTrue(qnaNotificationList.containsAll((List<Notification>) model.get("qnaNotificationList")));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("읽지 않은 알림들 모두 읽기")
    @Test
    public void readNotifications() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Notification notification = notificationFactory.createNotification(account, NotificationType.ACCOUNT_GRADE_CHANGED);

        assertFalse(notification.isChecked());
        mockMvc.perform(post("/notifications/read")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/notifications"))
                .andExpect(authenticated().withUsername(TEST_EMAIL));
        assertTrue(notification.isChecked());
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("읽은 알림들 삭제")
    @Test
    public void deleteNotifications() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Notification notification = notificationFactory.createNotification(account, NotificationType.ACCOUNT_GRADE_CHANGED);

        notification.setChecked(true);
        mockMvc.perform(post("/notifications/delete")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/notifications/old"))
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertTrue(notificationRepository.findAll().isEmpty());
    }

}
