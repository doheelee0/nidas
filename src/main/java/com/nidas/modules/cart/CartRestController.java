package com.nidas.modules.cart;

import com.nidas.infra.exception.InvalidParameterException;
import com.nidas.modules.account.Account;
import com.nidas.modules.account.CurrentAccount;
import com.nidas.modules.cart.form.CartForm;
import com.nidas.modules.cart.form.CartIdListForm;
import com.nidas.modules.cart.form.QuantityForm;
import com.nidas.modules.product.Product;
import com.nidas.modules.product.ProductService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.util.List;

@RestController
@RequiredArgsConstructor
public class CartRestController {

    private final ProductService productService;
    private final CartService cartService;
    private final CartRepository cartRepository;

    @PostMapping("/cart/add/product/{id}")
    public ResponseEntity addCart(@PathVariable Long id, @CurrentAccount Account account,
                                  @Valid @RequestBody CartForm cartForm, Errors errors) {
        if (errors.hasErrors()) {
            String message = cartForm.isOrderCheck()
                    ? "잘못된 값이 전달되어 물건 구매에 실패했습니다."
                    : "잘못된 값이 전달되어 장바구니에 물품을 담지 못했습니다.";
            throw new InvalidParameterException(message);
        }
        Product product = productService.getProduct(id);
        cartService.saveNewCart(product, account, cartForm);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/cart/{id}/update/quantity")
    public ResponseEntity updateQuantity(@PathVariable Long id, @CurrentAccount Account account,
                                         @Valid @RequestBody QuantityForm quantityForm, Errors errors) {
        if (errors.hasErrors()) {
            throw new InvalidParameterException(errors.getFieldError("quantity").getDefaultMessage());
        }
        Cart cart = cartService.getCart(id, account);
        cartService.updateQuantity(cart, quantityForm);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/cart/{id}/remove")
    public ResponseEntity removeCart(@PathVariable Long id, @CurrentAccount Account account) {
        Cart cart = cartService.getCart(id, account);
        cartService.delete(cart);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/cart/remove")
    public ResponseEntity removeCartItems(@CurrentAccount Account account,
                                          @Valid @RequestBody CartIdListForm cartIdListForm, Errors errors) {
        if (errors.hasErrors()) {
            throw new InvalidParameterException(errors.getFieldError("idList").getDefaultMessage());
        }
        List<Cart> cartList = cartService.getCartList(cartIdListForm.getIdList(), account);
        cartService.deleteAll(cartList);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/cart/order")
    public ResponseEntity orderCartItems(@CurrentAccount Account account,
                                         @Valid @RequestBody CartIdListForm cartIdListForm, Errors errors) {
        if (errors.hasErrors()) {
            throw new InvalidParameterException(errors.getFieldError("idList").getDefaultMessage());
        }
        List<Cart> accountCartList = cartRepository.findCartWithProductDetailsByAccount(account);
        List<Cart> cartList = cartService.getCartList(cartIdListForm.getIdList(), account);
        cartService.checkCartToOrder(accountCartList, cartList, true);
        return ResponseEntity.ok().build();
    }

}
