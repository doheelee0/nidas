package com.nidas.modules.product.converter;

import com.nidas.modules.product.MainCategory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

@Component
public class MainCategoryConverter implements Converter<String, MainCategory> {

    @Override
    public MainCategory convert(String source) {
        return source.isEmpty() ? null : MainCategory.valueOf(source.toUpperCase());
    }

}
