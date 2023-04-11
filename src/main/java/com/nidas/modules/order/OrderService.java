package com.nidas.modules.order;

import com.nidas.infra.config.AppProperties;
import com.nidas.infra.exception.InvalidParameterException;
import com.nidas.infra.exception.ResourceNotFoundException;
import com.nidas.modules.account.Account;
import com.nidas.modules.accountevent.AccountEventService;
import com.nidas.modules.cart.Cart;
import com.nidas.modules.order.event.OrderStatusChangedEvent;
import com.nidas.modules.order.form.OrderForm;
import com.nidas.modules.product.ProductDetails;
import com.nidas.modules.product.ProductService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

@Service
@Transactional
@RequiredArgsConstructor
public class OrderService {

    private final AccountEventService accountEventService;
    private final ProductService productService;
    private final OrderRepository orderRepository;
    private final OrderDetailsRepository orderDetailsRepository;
    private final ModelMapper modelMapper;
    private final AppProperties appProperties;
    private final ApplicationEventPublisher eventPublisher;

    public void processOrder(List<Cart> cartList, Account account, OrderForm orderForm) {
        checkIfAvailablePayment(cartList, account, orderForm.getMileageUsage());
        // 결제 처리 및 결제 정보 저장...
        ProductDetails[] productDetailsArray = cartList.stream().map(Cart::getProductDetails).toArray(ProductDetails[]::new);
        Integer[] priceArray = Arrays.stream(productDetailsArray).map(pd -> pd.getProduct().getDiscountedPrice()).toArray(Integer[]::new);
        Integer[] quantityArray = cartList.stream().map(Cart::getQuantity).toArray(Integer[]::new);
        Order newOrder = createNewOrder(productDetailsArray, priceArray, quantityArray, account, orderForm);
        accountEventService.updateOrderInfo(account, newOrder.getTotalPrice(), newOrder.getMileageUsage(), newOrder.getOrderDetails().size());
        productService.updateOrderInfo(productDetailsArray, priceArray, quantityArray);
    }

    private void checkIfAvailablePayment(List<Cart> cartList, Account account, Long mileageUsage) {
        if (cartList.stream().anyMatch(cart -> !cart.canOrder())) {
            throw new InvalidParameterException("주문할 수 없는 상품이 있습니다.");
        }
        if (!account.canOrder(mileageUsage)) {
            throw new InvalidParameterException("주문할 수 없는 상태입니다.");
        }
    }

    private Order createNewOrder(ProductDetails[] productDetailsArray, Integer[] priceArray, Integer[] quantityArray,
                                 Account account, OrderForm orderForm) {
        Order newOrder = modelMapper.map(orderForm, Order.class);
        newOrder.setOrderNumber(generateOrderNumber());
        newOrder.setCreatedDateTime(LocalDateTime.now());
        newOrder.setAccount(account);

        long totalPrice = 0l;
        for (int i = 0; i < productDetailsArray.length; i++) {
            ProductDetails productDetails = productDetailsArray[i];
            Integer price = priceArray[i];
            Integer quantity = quantityArray[i];

            OrderDetails newOrderDetails = new OrderDetails();
            newOrderDetails.setQuantity(quantity);
            newOrderDetails.setUnitPrice(price);
            newOrderDetails.setStatus(OrderStatus.PAID);
            newOrderDetails.setProductDetails(productDetails);
            newOrder.addOrderDetails(newOrderDetails);
            totalPrice += (long) price * quantity;
        }

        newOrder.setTotalPrice(totalPrice);
        newOrder.setDeliveryPrice(totalPrice < appProperties.getDeliveryFreeBasis() ? appProperties.getDeliveryPrice() : 0);

        if (newOrder.getMileageUsage() > newOrder.getTotalPrice() + newOrder.getDeliveryPrice()) {
            throw new InvalidParameterException("마일리지 금액이 주문 금액을 초과합니다.");
        }
        return orderRepository.save(newOrder);
    }

    private String generateOrderNumber() {
        Random rand = new Random();
        int randomNumber = rand.nextInt(90_000_000) + 10_000_000; // 10000000 ~ 99999999
        return LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd")) + randomNumber;
    }

    public Order getOrder(String orderNumber, Account account) {
        Order order = orderRepository.findByOrderNumberAndAccount(orderNumber, account);
        if (order == null) {
            throw new ResourceNotFoundException("해당 주문내역이 존재하지 않습니다.");
        }
        return order;
    }

    public OrderDetails getOrderDetails(Long id, Account account) {
        OrderDetails orderDetails = orderDetailsRepository.findByIdAndOrder_Account(id, account);
        checkIfExistingOrderDetails(orderDetails);
        return orderDetails;
    }

    public OrderDetails getOrderDetailsToUpdateStatus(Long id, Account account) {
        OrderDetails orderDetails = orderDetailsRepository.findOrderDetailsWithOrderAndAccountByIdAndOrder_Account(id, account);
        checkIfExistingOrderDetails(orderDetails);
        return orderDetails;
    }

    private void checkIfExistingOrderDetails(OrderDetails orderDetails) {
        if (orderDetails == null) {
            throw new ResourceNotFoundException("해당 주문내역이 존재하지 않습니다.");
        }
    }

    public void cancel(OrderDetails orderDetails, Account account) {
        if (!orderDetails.canCancel()) {
            throw new InvalidParameterException("결제완료 상태인 경우에만 주문 취소를 할 수 있습니다.");
        }
        // 환불 처리...
        updateStatus(orderDetails, OrderStatus.CANCELED, true);
        long orderDetailsTotalPrice = (long) orderDetails.getUnitPrice() * orderDetails.getQuantity();
        long orderDetailsMileage = (long) (orderDetails.getOrder().getMileageUsage() * ((double) orderDetailsTotalPrice / orderDetails.getOrder().getTotalPrice()));
        accountEventService.updateOrderInfo(account, -orderDetailsTotalPrice, -orderDetailsMileage, -1);
        productService.updateOrderInfo(new ProductDetails[]{orderDetails.getProductDetails()}, new Integer[]{orderDetails.getUnitPrice()}, new Integer[]{-orderDetails.getQuantity()});
    }

    public void updateStatus(OrderDetails orderDetails, OrderStatus orderStatus, boolean notifyingByEvent) {
        orderDetails.setStatus(orderStatus);
        if (orderStatus == OrderStatus.DELIVERED && orderDetails.getOrder().getArrivalDateTime() == null) {
            orderDetails.getOrder().setArrivalDateTime(LocalDateTime.now());
        }
        if (notifyingByEvent) {
            eventPublisher.publishEvent(new OrderStatusChangedEvent(orderDetails));
        }
    }

    public void markAsWrittenReview(OrderDetails orderDetails) {
        orderDetails.setReviewed(true);
    }

}
