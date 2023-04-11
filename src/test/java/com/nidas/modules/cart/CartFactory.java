package com.nidas.modules.cart;

import com.nidas.modules.account.Account;
import com.nidas.modules.product.Product;
import com.nidas.modules.product.ProductDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Component
public class CartFactory {

    @Autowired private CartRepository cartRepository;

    public Cart createCart(ProductDetails productDetails, Account account) {
        Cart cart = new Cart();
        cart.setQuantity(1);
        cart.setCreatedDateTime(LocalDateTime.now());
        cart.setProductDetails(productDetails);
        cart.setAccount(account);
        return cartRepository.save(cart);
    }

    public List<Cart> createCarts(Product product, Account account) {
        List<Cart> carts = new ArrayList<>();
        Set<ProductDetails> details = product.getDetails();

        for (ProductDetails productDetails : details) {
            Cart cart = new Cart();
            cart.setQuantity(1);
            cart.setCreatedDateTime(LocalDateTime.now());
            cart.setProductDetails(productDetails);
            cart.setAccount(account);
            carts.add(cart);
        }
        return cartRepository.saveAll(carts);
    }

}
