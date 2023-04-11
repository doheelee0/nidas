package com.nidas.modules.order;

import com.nidas.infra.config.AppProperties;
import com.nidas.infra.config.TestProperties;
import com.nidas.modules.account.Account;
import com.nidas.modules.product.Product;
import com.nidas.modules.product.ProductDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Random;
import java.util.Set;

@Component
public class OrderFactory {

    @Autowired private OrderRepository orderRepository;
    @Autowired private AppProperties appProperties;
    @Autowired private TestProperties testProperties;

    public Order createOrder(Product product, Account account) {
        Order order = new Order();

        Set<ProductDetails> details = product.getDetails();
        int discountedPrice = product.getDiscountedPrice();
        int quantity = 1;
        long totalPrice = 0;

        for (ProductDetails productDetails : details) {
            OrderDetails orderDetails = new OrderDetails();
            orderDetails.setQuantity(quantity);
            orderDetails.setUnitPrice(discountedPrice);
            orderDetails.setStatus(OrderStatus.PAID);
            orderDetails.setProductDetails(productDetails);
            order.addOrderDetails(orderDetails);
            totalPrice += (long) discountedPrice * quantity;
        }
        order.setDeliveryPrice(totalPrice < appProperties.getDeliveryFreeBasis() ? appProperties.getDeliveryPrice() : 0);
        order.setTotalPrice(totalPrice);
        order.setAccount(account);
        order.setCreatedDateTime(LocalDateTime.now());
        order.setReceiver(account.getName());
        order.setPhoneNumber(account.getPhoneNumber());
        order.setOrderNumber(generateOrderNumber());
        order.setAddress1(testProperties.getAddress1());
        order.setAddress2(testProperties.getAddress2());
        order.setAddress3(testProperties.getAddress3());

        return orderRepository.save(order);
    }

    private String generateOrderNumber() {
        Random rand = new Random();
        int randomNumber = rand.nextInt(90_000_000) + 10_000_000; // 10000000 ~ 99999999
        return LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd")) + randomNumber;
    }

}
