package com.nidas.infra.mail;

import com.icegreen.greenmail.util.GreenMail;
import com.icegreen.greenmail.util.GreenMailUtil;
import com.icegreen.greenmail.util.ServerSetupTest;
import com.nidas.infra.config.TestConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.context.ActiveProfiles;

import javax.mail.Message;
import javax.mail.MessagingException;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Import({TestConfig.class})
public class EmailSendingTest {

    private GreenMail greenMail;
    private EmailService emailService;
    @Autowired private JavaMailSender javaMailSender;

    @BeforeEach
    public void setup(@Value("${test.mail.username}") String username,
                      @Value("${test.mail.password}") String password) {
        emailService = new HtmlEmailService(javaMailSender);
        greenMail = new GreenMail(ServerSetupTest.SMTP);
        greenMail.setUser(username, password);
        greenMail.start();
    }

    @AfterEach
    public void end() {
        greenMail.stop();
    }

    @DisplayName("SMTP 이메일을 제대로 보내는지 확인")
    @Test
    public void sendSMTPEmail() throws Exception {
        String to = "test@email.com";
        String subject = "some subject";
        String message = "<p>some body text</p>";

        sendTestMails(to, subject, message);

        assertThat(greenMail.waitForIncomingEmail(5000, 1)).isTrue();

        Message[] messages = greenMail.getReceivedMessages();
        assertThat(messages.length).isEqualTo(1);

        assertThat(messages[0].getSubject()).isEqualTo(subject);
        assertThat(GreenMailUtil.getBody(messages[0]).trim()).isEqualTo(message);
    }

    private void sendTestMails(String to, String subject, String message) throws MessagingException {
        EmailMessage emailMessage = EmailMessage.builder()
                .to(to)
                .subject(subject)
                .message(message)
                .build();
        emailService.sendEmail(emailMessage);
    }

}
