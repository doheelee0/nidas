package com.nidas.infra.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.util.Properties;

import static org.mockito.Mockito.mock;

@TestConfiguration
public class TestConfig {

    @Bean
    @Primary
    ApplicationEventPublisher publisher() {
        return mock(ApplicationEventPublisher.class);
    }

    @Bean
    public JavaMailSender emailSender(@Value("${test.mail.host}") String host,
                                      @Value("${test.mail.port}") Integer port,
                                      @Value("${test.mail.username}") String username,
                                      @Value("${test.mail.password}") String password) {
        JavaMailSenderImpl javaMailSender = new JavaMailSenderImpl();
        javaMailSender.setHost(host);
        javaMailSender.setPort(port);
        javaMailSender.setUsername(username);
        javaMailSender.setPassword(password);

        Properties mailProps = new Properties();
        mailProps.setProperty("mail.transport.protocol", "smtp");
        mailProps.setProperty("mail.smtp.auth", "true");
        mailProps.setProperty("mail.smtp.timeout", "5000");
        mailProps.setProperty("mail.smtp.starttls.enable", "true");
        javaMailSender.setJavaMailProperties(mailProps);
        return javaMailSender;
    }

}
