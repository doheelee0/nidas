package com.nidas.infra.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@Getter @Setter
@ConfigurationProperties("app")
public class AppProperties {

    private String host;

    private int deliveryFreeBasis;

    private int deliveryPrice;

    private int minQuantity;

    private int maxQuantity;

}
