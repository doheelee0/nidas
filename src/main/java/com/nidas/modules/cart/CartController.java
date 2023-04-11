package com.nidas.modules.cart;

import com.nidas.infra.config.AppProperties;
import com.nidas.modules.account.Account;
import com.nidas.modules.account.CurrentAccount;
import com.nidas.modules.cart.validator.CartFormValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;

import java.util.List;

@Controller
@RequiredArgsConstructor
public class CartController {

    private final CartRepository cartRepository;
    private final CartFormValidator cartFormValidator;
    private final AppProperties appProperties;

    @InitBinder("cartForm")
    public void validatePasswordForm(WebDataBinder webDataBinder) {
        webDataBinder.addValidators(cartFormValidator);
    }

    @GetMapping("/cart-list")
    public String getCartList(@CurrentAccount Account account, Model model) {
        List<Cart> cartList = cartRepository.findCartWithProductDetailsAndProductByAccount(account);
        model.addAttribute("cartList", cartList);
        model.addAttribute("deliveryFreeBasis", appProperties.getDeliveryFreeBasis());
        model.addAttribute("deliveryPrice", appProperties.getDeliveryPrice());
        model.addAttribute("minQuantity", appProperties.getMinQuantity());
        model.addAttribute("maxQuantity", appProperties.getMaxQuantity());
        return "cart/cart-list";
    }

}
