package com.nidas.modules.faq;

import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

@Component
public class FaqTypeConverter implements Converter<String, FaqType> {

    @Override
    public FaqType convert(String source) {
        try {
            return FaqType.valueOf(source.toUpperCase());
        } catch (IllegalArgumentException | NullPointerException e) {
            return null;
        }
    }

}
