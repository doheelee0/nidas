package com.nidas.modules.order;

import com.nidas.infra.config.AppProperties;
import com.nidas.modules.account.Account;
import com.nidas.modules.account.CurrentAccount;
import com.nidas.modules.cart.Cart;
import com.nidas.modules.cart.CartRepository;
import com.nidas.modules.order.form.AdminOrderSearchForm;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.List;

@Controller
@RequiredArgsConstructor
public class OrderController {

    private final OrderService orderService;
    private final OrderRepository orderRepository;
    private final OrderDetailsRepository orderDetailsRepository;
    private final CartRepository cartRepository;
    private final AppProperties appProperties;

    @GetMapping("/order")
    public String orderForm(@CurrentAccount Account account, Model model) {
        List<Cart> cartList = cartRepository.findCartWithProductDetailsAndProductByAccountAndOrderCheckTrue(account);
        if (cartList.isEmpty()) {
            return "redirect:/";
        }
        model.addAttribute(account);
        model.addAttribute(cartList);
        model.addAttribute("deliveryFreeBasis", appProperties.getDeliveryFreeBasis());
        model.addAttribute("deliveryPrice", appProperties.getDeliveryPrice());
        return "order/make-order";
    }

    @GetMapping("/order/finished")
    public String orderFinishedForm() {
        return "order/order-finished";
    }

    @GetMapping("/mypage/order-list")
    public String getOrderList(@CurrentAccount Account account, Model model) {
        List<OrderStatus> statusList = List.of(OrderStatus.PAID, OrderStatus.PRODUCT_READY, OrderStatus.DELIVERING, OrderStatus.DELIVERED);
        List<OrderDetails> orderDetailsList = orderDetailsRepository.findByOrder_AccountAndStatusInOrderByOrder_CreatedDateTimeDesc(account, statusList);
        model.addAttribute("orderDetailsList", orderDetailsList);
        model.addAttribute(account);
        return "order/order-list";
    }

    @GetMapping("/mypage/order/{orderNumber}")
    public String viewOrderInfo(@PathVariable String orderNumber, @CurrentAccount Account account, Model model) {
        Order order = orderService.getOrder(orderNumber, account);
        model.addAttribute(order);
        model.addAttribute(account);
        return "order/details";
    }

    @GetMapping("/admin/management/order")
    public String getAdminOrderList(@PageableDefault(size = 20) Pageable pageable,
                                    AdminOrderSearchForm adminOrderSearchForm, Model model) {
        Page<Order> orderPage = orderRepository.findByAdminOrderSearchForm(adminOrderSearchForm, pageable);
        model.addAttribute("orderPage", orderPage);
        return "order/admin/order-management";
    }

}
