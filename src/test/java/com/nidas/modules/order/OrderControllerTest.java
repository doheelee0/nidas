package com.nidas.modules.order;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nidas.infra.AbstractContainerBaseTest;
import com.nidas.infra.config.MockMvcTest;
import com.nidas.infra.config.TestConfig;
import com.nidas.infra.config.TestProperties;
import com.nidas.modules.account.Account;
import com.nidas.modules.account.AccountRepository;
import com.nidas.modules.account.Membership;
import com.nidas.modules.account.WithAccount;
import com.nidas.modules.accountevent.event.AccountGradeChangedEvent;
import com.nidas.modules.cart.Cart;
import com.nidas.modules.cart.CartFactory;
import com.nidas.modules.cart.CartRepository;
import com.nidas.modules.order.event.OrderStatusChangedEvent;
import com.nidas.modules.order.form.OrderForm;
import com.nidas.modules.product.Product;
import com.nidas.modules.product.ProductDetails;
import com.nidas.modules.product.ProductFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@MockMvcTest
@Import({TestConfig.class})
public class OrderControllerTest extends AbstractContainerBaseTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ProductFactory productFactory;
    @Autowired private CartFactory cartFactory;
    @Autowired private OrderFactory orderFactory;
    @Autowired private CartRepository cartRepository;
    @Autowired private AccountRepository accountRepository;
    @Autowired private OrderRepository orderRepository;
    @Autowired private TestProperties testProperties;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private ApplicationEventPublisher eventPublisher;

    private final String TEST_EMAIL = "test@email.com";

    @BeforeEach
    public void setup() {
        reset(eventPublisher);
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("주문 화면 보이는지 테스트")
    @Test
    public void orderForm() throws Exception {
        Product product = productFactory.createProduct();
        List<Cart> carts = cartFactory.createCarts(product, accountRepository.findByEmail(TEST_EMAIL));
        carts.forEach(cart -> cart.setOrderCheck(true));

        mockMvc.perform(get("/order"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("order/make-order"))
                .andExpect(model().attributeExists("account", "cartList", "deliveryFreeBasis", "deliveryPrice"))
                .andExpect(model().attribute("cartList", carts))
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("주문 화면 보이는지 테스트 - 주문 상품이 없는 경우")
    @Test
    public void updateProductForm_no_items() throws Exception {
        mockMvc.perform(get("/order"))
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/"))
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("주문 처리 - 성공")
    @Test
    public void order() throws Exception {
        Product product = productFactory.createProduct();
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        List<Cart> carts = cartFactory.createCarts(product, account);

        account.setMileage(5000l);
        carts.forEach(cart -> cart.setOrderCheck(true));
        Long totalPayment = carts.stream().mapToLong(cart -> cart.getProductDetails().getProduct().getDiscountedPrice() * cart.getQuantity()).sum();

        OrderForm orderForm = createOrderForm(carts, account);
        mockMvc.perform(post("/order")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(orderForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        Order order = orderRepository.findAll().get(0);
        assertNotNull(order);
        assertEquals(order.getTotalPrice(), totalPayment);

        List<OrderDetails> orderDetailsList = order.getOrderDetails();
        assertEquals(orderDetailsList.size(), carts.size());
        for (int i = 0; i < orderDetailsList.size(); i++) { // 선택한 카트 물품들로 주문이 생성되었는지 확인
            OrderDetails orderDetails = orderDetailsList.get(i);
            Cart cart = carts.get(i);

            assertEquals(orderDetails.getProductDetails(), cart.getProductDetails());
            assertEquals(orderDetails.getQuantity(), cart.getQuantity());
            assertEquals(orderDetails.getUnitPrice(), cart.getProductDetails().getProduct().getDiscountedPrice());
            assertEquals(orderDetails.getStatus(), OrderStatus.PAID);
        }

        assertEquals(account.getMileage(), 0); // 주문 후 변경된 유저 정보 확인
        assertEquals(account.getTotalOrder(), carts.size());
        assertEquals(account.getTotalPayment(), totalPayment);
        assertEquals(account.getMembership(), Membership.GOLD);
        verify(eventPublisher).publishEvent(any(AccountGradeChangedEvent.class)); // 멤버쉽 변경 이벤트가 발생됨을 확인

        assertEquals(product.getEntireSalesQuantity(), carts.stream().mapToInt(Cart::getQuantity).sum()); // 주문 후 변경된 상품 정보 확인
        assertEquals(product.getEntireSalesAmount(), totalPayment);
        product.getDetails().forEach(productDetails -> assertEquals(productDetails.getStock(), 99));

        assertTrue(cartRepository.findAll().isEmpty()); // 주문 후 카트 물품 삭제 되었는지 확인
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("주문 처리 - 주문 상품 목록이 없는 경우")
    @Test
    public void order_no_cart_id() throws Exception {
        OrderForm orderForm = createOrderForm(Collections.emptyList(), accountRepository.findByEmail(TEST_EMAIL));
        mockMvc.perform(post("/order")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(orderForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("주문 처리 - 주문중이지 않은 물품이 있는 경우")
    @Test
    public void order_not_ordering_items() throws Exception {
        Product product = productFactory.createProduct();
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        List<Cart> carts = cartFactory.createCarts(product, account);

        carts.forEach(cart -> cart.setOrderCheck(false));

        OrderForm orderForm = createOrderForm(carts, account);
        mockMvc.perform(post("/order")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(orderForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("주문 처리 - 인증되지 않은 사용자")
    @Test
    public void order_not_verified() throws Exception {
        Product product = productFactory.createProduct();
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        List<Cart> carts = cartFactory.createCarts(product, account);

        account.setEmailVerified(false);
        carts.forEach(cart -> cart.setOrderCheck(true));

        OrderForm orderForm = createOrderForm(carts, account);
        mockMvc.perform(post("/order")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(orderForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("주문 처리 - 마일리지 문제")
    @Test
    public void order_not_enough_mileage() throws Exception {
        // 가진 값보다 큰 값인 경우
        Product product = productFactory.createProduct();
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        List<Cart> carts = cartFactory.createCarts(product, account);

        carts.forEach(cart -> cart.setOrderCheck(true));

        OrderForm orderForm = createOrderForm(carts, account);
        orderForm.setMileageUsage(5000l);
        mockMvc.perform(post("/order")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(orderForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        // 마일리지 값이 주문 금액보다 큰 경우
        account.setMileage(1000000l);
        orderForm.setMileageUsage(account.getMileage());
        mockMvc.perform(post("/order")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(orderForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("주문 완료 화면 보이는지 테스트")
    @Test
    public void orderFinishedForm() throws Exception {
        mockMvc.perform(get("/order/finished"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("order/order-finished"))
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    private OrderForm createOrderForm(List<Cart> carts, Account account) {
        OrderForm orderForm = new OrderForm();
        orderForm.setReceiver(account.getName());
        orderForm.setAddress1(testProperties.getAddress1());
        orderForm.setAddress2(testProperties.getAddress2());
        orderForm.setAddress3(testProperties.getAddress3());
        orderForm.setPhoneNumber(account.getPhoneNumber());
        orderForm.setDeliveryRequest("test");
        orderForm.setMileageUsage(account.getMileage());
        orderForm.setCartIdList(carts.stream().map(Cart::getId).collect(Collectors.toSet()));
        return orderForm;
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("주문 목록 화면 보이는지 테스트")
    @Test
    public void getOrderList() throws Exception {
        Product product = productFactory.createProduct();
        Order order = orderFactory.createOrder(product, accountRepository.findByEmail(TEST_EMAIL));

        Map<String, Object> model = mockMvc.perform(get("/mypage/order-list"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("order/order-list"))
                .andExpect(model().attributeExists("account", "orderDetailsList"))
                .andExpect(authenticated().withUsername(TEST_EMAIL))
                .andReturn().getModelAndView().getModel();

        List<OrderDetails> orderDetailsList = (List<OrderDetails>) model.get("orderDetailsList");
        assertEquals(order.getOrderDetails().size(), orderDetailsList.size());
        assertTrue(order.getOrderDetails().containsAll(orderDetailsList));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("주문 상세 화면 보이는지 테스트")
    @Test
    public void viewOrderInfo() throws Exception {
        Product product = productFactory.createProduct();
        Order order = orderFactory.createOrder(product, accountRepository.findByEmail(TEST_EMAIL));

        mockMvc.perform(get("/mypage/order/" + order.getOrderNumber()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("order/details"))
                .andExpect(model().attributeExists("account", "order"))
                .andExpect(model().attribute("order", order))
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("주문 취소 - 성공")
    @Test
    public void cancelOrderDetails() throws Exception {
        Product product = productFactory.createProduct();
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Order order = orderFactory.createOrder(product, account);
        OrderDetails orderDetails = order.getOrderDetails().get(0);
        ProductDetails productDetails = orderDetails.getProductDetails();

        // 주문 정보를 Account와 Product에 반영
        order.setMileageUsage(1000l);
        account.setTotalOrder(order.getOrderDetails().size());
        account.setTotalPayment(order.getTotalPrice());
        product.setEntireSalesQuantity(order.getOrderDetails().stream().mapToInt(OrderDetails::getQuantity).sum());
        product.setEntireSalesAmount(order.getTotalPrice());
        productDetails.setStock(productDetails.getStock() - orderDetails.getQuantity());

        // 취소하기 전의 데이터
        Integer prevTotalOrder = account.getTotalOrder();
        Long prevTotalPayment = account.getTotalPayment();
        Integer prevEntireSalesQuantity = product.getEntireSalesQuantity();
        Long prevEntireSalesAmount = product.getEntireSalesAmount();
        Integer prevStock = productDetails.getStock();

        mockMvc.perform(post("/order/details/" + orderDetails.getId() + "/cancel")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        long orderDetailsTotalPrice = (long) orderDetails.getUnitPrice() * orderDetails.getQuantity();
        long mileage = (long) (order.getMileageUsage() * ((double) orderDetailsTotalPrice / order.getTotalPrice()));

        assertEquals(orderDetails.getStatus(), OrderStatus.CANCELED);
        verify(eventPublisher).publishEvent(any(OrderStatusChangedEvent.class)); // 주문 상태 변경 이벤트가 발생됨을 확인

        assertEquals(account.getTotalOrder(), prevTotalOrder - 1);
        assertEquals(account.getTotalPayment(),  prevTotalPayment - orderDetailsTotalPrice);
        assertEquals(account.getMileage(), mileage); // 상품을 사는데 사용된 마일리지 회수

        assertEquals(orderDetails.getProductDetails().getStock(), prevStock + orderDetails.getQuantity());
        assertEquals(product.getEntireSalesQuantity(), prevEntireSalesQuantity - orderDetails.getQuantity());
        assertEquals(product.getEntireSalesAmount(), prevEntireSalesAmount - orderDetailsTotalPrice);
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("주문 취소 - 결제완료 상태가 아닌 경우")
    @Test
    public void cancelOrderDetails_not_PAID_status() throws Exception {
        Product product = productFactory.createProduct();
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Order order = orderFactory.createOrder(product, account);
        OrderDetails orderDetails = order.getOrderDetails().get(0);

        orderDetails.setStatus(OrderStatus.PRODUCT_READY);
        mockMvc.perform(post("/order/details/" + orderDetails.getId() + "/cancel")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertNotEquals(orderDetails.getStatus(), OrderStatus.CANCELED);
    }

}
