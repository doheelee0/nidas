package com.nidas.modules.order;

import com.nidas.infra.exception.InvalidParameterException;
import com.nidas.modules.account.Account;
import com.nidas.modules.account.AccountService;
import com.nidas.modules.account.CurrentAccount;
import com.nidas.modules.cart.Cart;
import com.nidas.modules.cart.CartService;
import com.nidas.modules.order.form.AdminOrderInfo;
import com.nidas.modules.order.form.OrderForm;
import com.nidas.modules.order.form.OrderStatusForm;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class OrderRestController {

    private final AccountService accountService;
    private final CartService cartService;
    private final OrderService orderService;
    private final OrderRepository orderRepository;
    private final ModelMapper modelMapper;

    @PostMapping("/order")
    public ResponseEntity order(@Valid @RequestBody OrderForm orderForm, Errors errors, @CurrentAccount Account account) {
        if (errors.hasErrors()) {
            throw new InvalidParameterException(errors.getAllErrors().get(0).getDefaultMessage());
        }
        List<Cart> cartList = cartService.getCartListToOrder(orderForm.getCartIdList(), account);
        orderService.processOrder(cartList, account, orderForm);
        cartService.deleteAll(cartList);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/order/details/{id}/cancel")
    public ResponseEntity cancelOrderDetails(@PathVariable Long id, @CurrentAccount Account account) {
        OrderDetails orderDetails = orderService.getOrderDetails(id, account);
        orderService.cancel(orderDetails, account);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/admin/management/account/{id}/order")
    public ResponseEntity getAccountOrderList(@PathVariable("id") Account account) {
        List<AdminOrderInfo> orderList = orderRepository.findByAccount(account).stream()
                .map(order -> {
                    AdminOrderInfo adminOrderInfo = modelMapper.map(order, AdminOrderInfo.class);
                    adminOrderInfo.setOrderDetailsList(order.getOrderDetails());
                    return adminOrderInfo;
                }).collect(Collectors.toList());
        return ResponseEntity.ok().body(orderList);
    }

    @PostMapping("/admin/order/details/{id}/update/status")
    public ResponseEntity updateOrderStatus(@PathVariable Long id, @Valid @RequestBody OrderStatusForm orderStatusForm, Errors errors) {
        if (errors.hasErrors()) {
            throw new InvalidParameterException(errors.getAllErrors().get(0).getDefaultMessage());
        }
        Account account = accountService.getAccount(orderStatusForm.getAccountId());
        OrderDetails orderDetails = orderService.getOrderDetailsToUpdateStatus(id, account);
        orderService.updateStatus(orderDetails, orderStatusForm.getOrderStatus(), true);
        return ResponseEntity.ok().build();
    }

}
