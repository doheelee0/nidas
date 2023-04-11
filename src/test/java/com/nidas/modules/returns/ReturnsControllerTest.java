package com.nidas.modules.returns;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nidas.infra.AbstractContainerBaseTest;
import com.nidas.infra.config.MockMvcTest;
import com.nidas.modules.account.Account;
import com.nidas.modules.account.AccountRepository;
import com.nidas.modules.account.WithAccount;
import com.nidas.modules.order.Order;
import com.nidas.modules.order.OrderDetails;
import com.nidas.modules.order.OrderFactory;
import com.nidas.modules.order.OrderStatus;
import com.nidas.modules.product.Product;
import com.nidas.modules.product.ProductFactory;
import com.nidas.modules.returns.form.ReturnsForm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@MockMvcTest
public class ReturnsControllerTest extends AbstractContainerBaseTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ProductFactory productFactory;
    @Autowired private OrderFactory orderFactory;
    @Autowired private ReturnsFactory returnsFactory;
    @Autowired private AccountRepository accountRepository;
    @Autowired private ReturnsRepository returnsRepository;
    @Autowired private ObjectMapper objectMapper;

    private final String TEST_EMAIL = "test@email.com";

    @WithAccount(TEST_EMAIL)
    @DisplayName("교환 신청 - 성공")
    @Test
    public void applyForExchange() throws Exception {
        Product product = productFactory.createProduct();
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Order order = orderFactory.createOrder(product, account);
        OrderDetails orderDetails = order.getOrderDetails().get(0);

        order.setArrivalDateTime(LocalDateTime.now());
        orderDetails.setStatus(OrderStatus.DELIVERED);

        ReturnsForm returnsForm = createReturnsForm(ReturnsType.EXCHANGE_MIND_CHANGED, product.getThumbnail());

        mockMvc.perform(post("/order/details/" + orderDetails.getId() + "/exchange")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(returnsForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertNotNull(returnsRepository.findByAccount(account));
        assertEquals(orderDetails.getStatus(), OrderStatus.EXCHANGING);
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("교환 신청 - 잘못된 교환 사유값 전달")
    @Test
    public void applyForExchange_wrong_type() throws Exception {
        Product product = productFactory.createProduct();
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Order order = orderFactory.createOrder(product, account);
        OrderDetails orderDetails = order.getOrderDetails().get(0);

        order.setArrivalDateTime(LocalDateTime.now());
        orderDetails.setStatus(OrderStatus.DELIVERED);

        // 환불 사유 전달
        ReturnsForm returnsForm = createReturnsForm(ReturnsType.RETURN_DELIVERED_BROKEN, product.getThumbnail());
        mockMvc.perform(post("/order/details/" + orderDetails.getId() + "/exchange")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(returnsForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertTrue(returnsRepository.findByAccount(account).isEmpty());
        assertNotEquals(orderDetails.getStatus(), OrderStatus.EXCHANGING);
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("교환 신청 - 교환 신청을 할 수 없는 상태인 경우")
    @Test
    public void applyForExchange_cannot_apply() throws Exception {
        Product product = productFactory.createProduct();
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        OrderDetails orderDetails = orderFactory.createOrder(product, account).getOrderDetails().get(0); // 결제완료 상태

        ReturnsForm returnsForm = createReturnsForm(ReturnsType.EXCHANGE_MIND_CHANGED, product.getThumbnail());
        mockMvc.perform(post("/order/details/" + orderDetails.getId() + "/exchange")
                        .characterEncoding("utf8")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(returnsForm))
                        .with(csrf()))
                    .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertTrue(returnsRepository.findByAccount(account).isEmpty());
        assertNotEquals(orderDetails.getStatus(), OrderStatus.EXCHANGING);
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("환불 신청 - 성공")
    @Test
    public void applyForReturn() throws Exception {
        Product product = productFactory.createProduct();
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Order order = orderFactory.createOrder(product, account);
        OrderDetails orderDetails = order.getOrderDetails().get(0);

        order.setArrivalDateTime(LocalDateTime.now());
        orderDetails.setStatus(OrderStatus.DELIVERED);

        ReturnsForm returnsForm = createReturnsForm(ReturnsType.RETURN_DELIVERED_BROKEN, product.getThumbnail());
        mockMvc.perform(post("/order/details/" + orderDetails.getId() + "/return")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(returnsForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertNotNull(returnsRepository.findByAccount(account));
        assertEquals(orderDetails.getStatus(), OrderStatus.RETURNING);
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("환불 신청 - 잘못된 환불 사유값 전달")
    @Test
    public void applyForReturn_wrong_type() throws Exception {
        Product product = productFactory.createProduct();
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Order order = orderFactory.createOrder(product, account);
        OrderDetails orderDetails = order.getOrderDetails().get(0);

        order.setArrivalDateTime(LocalDateTime.now());
        orderDetails.setStatus(OrderStatus.DELIVERED);

        // 교환 사유 전달
        ReturnsForm returnsForm = createReturnsForm(ReturnsType.EXCHANGE_DELIVERED_BROKEN, product.getThumbnail());
        mockMvc.perform(post("/order/details/" + orderDetails.getId() + "/return")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(returnsForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertTrue(returnsRepository.findByAccount(account).isEmpty());
        assertNotEquals(orderDetails.getStatus(), OrderStatus.RETURNING);
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("환불 신청 - 환불 신청을 할 수 없는 상태인 경우")
    @Test
    public void applyForReturn_cannot_apply() throws Exception {
        Product product = productFactory.createProduct();
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        OrderDetails orderDetails = orderFactory.createOrder(product, account).getOrderDetails().get(0); // 결제완료 상태

        ReturnsForm returnsForm = createReturnsForm(ReturnsType.RETURN_DELIVERED_BROKEN, product.getThumbnail());
        mockMvc.perform(post("/order/details/" + orderDetails.getId() + "/return")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(returnsForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertTrue(returnsRepository.findByAccount(account).isEmpty());
        assertNotEquals(orderDetails.getStatus(), OrderStatus.RETURNING);
    }

    private ReturnsForm createReturnsForm(ReturnsType type, String image) {
        ReturnsForm returnsForm = new ReturnsForm();
        returnsForm.setType(type);
        returnsForm.setContent("test");
        returnsForm.setImage(image);
        return returnsForm;
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("취소/교환/환불 목록 페이지 보이는지 확인")
    @Test
    public void getCancelReturnsList() throws Exception {
        Product product = productFactory.createProduct();
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Order order = orderFactory.createOrder(product, account);
        List<OrderDetails> orderDetailsList = order.getOrderDetails();

        order.setArrivalDateTime(LocalDateTime.now());
        orderDetailsList.get(0).setStatus(OrderStatus.CANCELED);
        orderDetailsList.get(1).setStatus(OrderStatus.CANCELED);

        Returns returns1 = returnsFactory.createReturns(account, orderDetailsList.get(2));
        Returns returns2 = returnsFactory.createReturns(account, orderDetailsList.get(3));
        orderDetailsList.get(2).setStatus(OrderStatus.EXCHANGING);
        orderDetailsList.get(3).setStatus(OrderStatus.RETURNING);

        Returns returns3 = returnsFactory.createReturns(account, orderDetailsList.get(4));
        Returns returns4 = returnsFactory.createReturns(account, orderDetailsList.get(5));
        orderDetailsList.get(4).setStatus(OrderStatus.EXCHANGED);
        orderDetailsList.get(5).setStatus(OrderStatus.RETURNED);
        returns3.setCompletedDateTime(LocalDateTime.now());
        returns4.setCompletedDateTime(LocalDateTime.now());

        Map<String, Object> model = mockMvc.perform(get("/mypage/cancel-returns-list"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("returns/cancel-returns-list"))
                .andExpect(model().attributeExists("account", "cancelList", "returningList", "returnedList"))
                .andExpect(authenticated().withUsername(TEST_EMAIL))
                .andReturn().getModelAndView().getModel();

        List<OrderDetails> cancelList = (List<OrderDetails>) model.get("cancelList");
        List<Returns> returningList = (List<Returns>) model.get("returningList");
        List<Returns> returnedList = (List<Returns>) model.get("returnedList");
        assertEquals(cancelList.size(), 2);
        assertEquals(returningList.size(), 2);
        assertEquals(returningList.size(), 2);
        assertTrue(cancelList.containsAll(List.of(orderDetailsList.get(0), orderDetailsList.get(1))));
        assertTrue(returningList.containsAll(List.of(returns1, returns2)));
        assertTrue(returnedList.containsAll(List.of(returns3, returns4)));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("교환/환불 신청 삭제 - 성공")
    @Test
    public void deleteReturns() throws Exception {
        Product product = productFactory.createProduct();
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Order order = orderFactory.createOrder(product, account);
        OrderDetails orderDetails = order.getOrderDetails().get(0);

        order.setArrivalDateTime(LocalDateTime.now());
        orderDetails.setStatus(OrderStatus.EXCHANGING);
        Returns returns = returnsFactory.createReturns(account, orderDetails);

        mockMvc.perform(post("/returns/" + returns.getId() + "/delete")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertTrue(returnsRepository.findById(returns.getId()).isEmpty());
        assertEquals(orderDetails.getStatus(), OrderStatus.DELIVERED);
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("교환/환불 신청 삭제 - 이미 처리가 완료된 경우")
    @Test
    public void deleteReturns_already_completed() throws Exception {
        Product product = productFactory.createProduct();
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Order order = orderFactory.createOrder(product, account);
        OrderDetails orderDetails = order.getOrderDetails().get(0);

        order.setArrivalDateTime(LocalDateTime.now());
        Returns returns = returnsFactory.createReturns(account, orderDetails);
        orderDetails.setStatus(OrderStatus.EXCHANGED); // 처리가 완료됨
        returns.setCompletedDateTime(LocalDateTime.now());

        mockMvc.perform(post("/returns/" + returns.getId() + "/delete")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertTrue(returnsRepository.findById(returns.getId()).isPresent());
        assertNotEquals(orderDetails.getStatus(), OrderStatus.DELIVERED);
    }

}
