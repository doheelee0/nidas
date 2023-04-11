package com.nidas.modules.cart.validator;

import com.nidas.modules.cart.form.CartForm;
import com.nidas.modules.cart.form.CartItemForm;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import java.util.HashSet;
import java.util.List;

@Component
public class CartFormValidator implements Validator {

    @Override
    public boolean supports(Class<?> clazz) {
        return clazz.isAssignableFrom(CartForm.class);
    }

    @Override
    public void validate(Object target, Errors errors) {
        CartForm cartForm = (CartForm) target;
        List<CartItemForm> itemList = cartForm.getItemList();

        if (itemList.size() != new HashSet<>(itemList).size()) {
            errors.rejectValue("itemList", "duplicate_itemList", new Object[]{itemList}, "중복되는 물품이 존재합니다.");
        }
    }

}
