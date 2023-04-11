package com.nidas.infra.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@Getter @Setter
@ConfigurationProperties("test")
public class TestProperties {

    private String email;

    private String password;

    private String name;

    private String gender;

    private String birthday;

    private String phoneNumber;

    private String address1;

    private String address2;

    private String address3;

}
