package com.nidas.modules.product.converter;

import com.nidas.modules.product.SubCategory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

@Component
public class SubCategoryConverter implements Converter<String, SubCategory> {

    @Override
    public SubCategory convert(String source) {
        return source.isEmpty() ? null : SubCategory.nameOf(source.toUpperCase());
    }

}
