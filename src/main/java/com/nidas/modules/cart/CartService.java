package com.nidas.modules.cart;

import com.nidas.infra.exception.ResourceNotFoundException;
import com.nidas.modules.account.Account;
import com.nidas.modules.cart.form.CartForm;
import com.nidas.modules.cart.form.CartItemForm;
import com.nidas.modules.cart.form.QuantityForm;
import com.nidas.modules.product.Product;
import com.nidas.modules.product.ProductDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Service
@Transactional
@RequiredArgsConstructor
public class CartService {

    private final CartRepository cartRepository;

    public void saveNewCart(Product product, Account account, CartForm cartForm) {
        List<Cart> accountCartList = cartRepository.findCartWithProductDetailsByAccount(account);
        List<Cart> cartList = updateExistingOrCreateNew(product, cartForm.getItemList(), account, accountCartList);
        checkCartToOrder(accountCartList, cartList, cartForm.isOrderCheck());
        cartRepository.saveAll(accountCartList); // 장바구니 내의 변경사항 모두 반영
    }

    private List<Cart> updateExistingOrCreateNew(Product product, List<CartItemForm> itemList, Account account, List<Cart> accountCartList) {
        List<Cart> cartList = new ArrayList<>();
        for (CartItemForm item : itemList) {
            ProductDetails productDetails = product.getProductDetails(item.getColor(), item.getSize());
            Cart cart = accountCartList.stream()
                    .filter(c -> productDetails.equals(c.getProductDetails())) // 해당 상품이 장바구니에 담겨있는지 확인
                    .findFirst()
                    .orElseGet(() -> {
                        Cart newCart = new Cart();
                        newCart.setProductDetails(productDetails);
                        newCart.setAccount(account);
                        accountCartList.add(newCart);
                        return newCart;
                    });
            cart.setQuantity(item.getQuantity());
            cart.setCreatedDateTime(LocalDateTime.now());
            cartList.add(cart);
        }
        return cartList;
    }

    public void checkCartToOrder(List<Cart> accountCartList, List<Cart> cartList, boolean isOrderCheck) {
        accountCartList.forEach(cart -> cart.setOrderCheck(false));
        cartList.stream().forEach(cart -> cart.setOrderCheck(isOrderCheck));
    }

    public void updateQuantity(Cart cart, QuantityForm quantityForm) {
        cart.setQuantity(quantityForm.getQuantity());
    }

    public Cart getCart(Long id, Account account) {
        Cart cart = cartRepository.findByIdAndAccount(id, account);
        if (cart == null) {
            throw new ResourceNotFoundException("해당하는 장바구니 상품이 존재하지 않습니다.");
        }
        return cart;
    }

    public List<Cart> getCartList(Set<Long> idList, Account account) {
        List<Cart> cartList = cartRepository.findByIdInAndAccount(idList, account);
        if (cartList.size() != idList.size()) {
            throw new ResourceNotFoundException("존재하지 않는 장바구니 상품이 있습니다.");
        }
        return cartList;
    }

    public List<Cart> getCartListToOrder(Set<Long> idList, Account account) {
        List<Cart> cartList = cartRepository.findCartWithProductDetailsAndProductByIdInAndAccount(idList, account);
        if (cartList.size() != idList.size()) {
            throw new ResourceNotFoundException("존재하지 않는 장바구니 상품이 있습니다.");
        }
        return cartList;
    }

    public void delete(Cart cart) {
        cartRepository.delete(cart);
    }

    public void deleteAll(List<Cart> cartList) {
        cartRepository.deleteAllInBatch(cartList);
    }

}
