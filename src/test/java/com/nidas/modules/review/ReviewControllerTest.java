package com.nidas.modules.review;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nidas.infra.AbstractContainerBaseTest;
import com.nidas.infra.config.MockMvcTest;
import com.nidas.modules.account.Account;
import com.nidas.modules.account.AccountRepository;
import com.nidas.modules.account.WithAccount;
import com.nidas.modules.order.OrderDetails;
import com.nidas.modules.order.OrderFactory;
import com.nidas.modules.order.OrderStatus;
import com.nidas.modules.product.Product;
import com.nidas.modules.product.ProductFactory;
import com.nidas.modules.review.form.ReviewForm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@MockMvcTest
public class ReviewControllerTest extends AbstractContainerBaseTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ProductFactory productFactory;
    @Autowired private OrderFactory orderFactory;
    @Autowired private ReviewFactory reviewFactory;
    @Autowired private AccountRepository accountRepository;
    @Autowired private ReviewRepository reviewRepository;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private ModelMapper modelMapper;

    private final String TEST_EMAIL = "test@email.com";

    @WithAccount(TEST_EMAIL)
    @DisplayName("리뷰를 작성할 수 있는 주문 목록 페이지 보이는지 확인")
    @Test
    public void getWritableReviewList() throws Exception {
        Product product = productFactory.createProduct();
        List<OrderDetails> orderDetailsList = orderFactory.createOrder(product, accountRepository.findByEmail(TEST_EMAIL)).getOrderDetails();
        orderDetailsList.forEach(orderDetails -> orderDetails.setStatus(OrderStatus.DELIVERED));

        Map<String, Object> model = mockMvc.perform(get("/mypage/writable-review-list"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("review/writable-review-list"))
                .andExpect(model().attributeExists("account", "orderDetailsList"))
                .andExpect(authenticated().withUsername(TEST_EMAIL))
                .andReturn().getModelAndView().getModel();

        List<OrderDetails> odList = (List<OrderDetails>) model.get("orderDetailsList");
        assertEquals(odList.size(), orderDetailsList.size());
        assertTrue(odList.containsAll(orderDetailsList));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("리뷰 작성 - 성공")
    @Test
    public void writeReview() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Product product = productFactory.createProduct();
        OrderDetails orderDetails = orderFactory.createOrder(product, account).getOrderDetails().get(0);
        orderDetails.setStatus(OrderStatus.DELIVERED);

        ReviewForm reviewForm = createReviewForm();
        mockMvc.perform(post("/order/details/" + orderDetails.getId() + "/review/write")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(reviewForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        Review review = reviewRepository.findByAccountAndDeletedFalse(account).get(0);
        assertNotNull(review);
        assertEquals(account.getMileage(), (long) review.getEarnedMileage());
        assertEquals(product.getReviewCount(), 1);
        assertEquals(product.getRank(), (double) review.getRank());
        assertTrue(orderDetails.isReviewed());
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("리뷰 작성 - 리뷰를 작성할 수 없는 주문 상태인 경우")
    @Test
    public void writeReview_wrong_order_status() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Product product = productFactory.createProduct();
        OrderDetails orderDetails = orderFactory.createOrder(product, account).getOrderDetails().get(0); // 결제완료 상태

        ReviewForm reviewForm = createReviewForm();
        mockMvc.perform(post("/order/details/" + orderDetails.getId() + "/review/write")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(reviewForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertTrue(reviewRepository.findByAccountAndDeletedFalse(account).isEmpty());
        assertEquals(account.getMileage(), 0);
        assertEquals(product.getReviewCount(), 0);
        assertEquals(product.getRank(), 0);
        assertFalse(orderDetails.isReviewed());
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("리뷰 작성 - 이미 리뷰를 작성한 경우")
    @Test
    public void writeReview_existed() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Product product = productFactory.createProduct();
        OrderDetails orderDetails = orderFactory.createOrder(product, account).getOrderDetails().get(0);
        reviewFactory.createReview(account, product, orderDetails);

        ReviewForm reviewForm = createReviewForm();
        mockMvc.perform(post("/order/details/" + orderDetails.getId() + "/review/write")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(reviewForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    private ReviewForm createReviewForm() {
        ReviewForm reviewForm = new ReviewForm();
        reviewForm.setRank(5);
        reviewForm.setContent("review test1");
        reviewForm.setImage(null);
        return reviewForm;
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("리뷰 목록 보이는지 확인")
    @Test
    public void getReviewList() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Product product = productFactory.createProduct();
        OrderDetails orderDetails = orderFactory.createOrder(product, account).getOrderDetails().get(0);

        List<Review> reviews = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            Review review = reviewFactory.createReview(account, product, orderDetails);
            if (i < 5) reviews.add(review);
            else review.setDeleted(true);
        }

        Map<String, Object> model = mockMvc.perform(get("/mypage/review-list"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("review/review-list"))
                .andExpect(model().attributeExists("account", "reviewList"))
                .andExpect(authenticated().withUsername(TEST_EMAIL))
                .andReturn().getModelAndView().getModel();

        List<Review> reviewList = (List<Review>) model.get("reviewList");
        assertEquals(reviews.size(), reviewList.size());
        reviewList.containsAll(reviews);
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("리뷰 수정 - 성공")
    @Test
    public void updateReview() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Product product = productFactory.createProduct();
        OrderDetails orderDetails = orderFactory.createOrder(product, account).getOrderDetails().get(0);
        Review review = reviewFactory.createReview(account, product, orderDetails);

        product.setRank((double) review.getRank()); // 5
        product.setReviewCount(1);

        ReviewForm reviewForm = modelMapper.map(review, ReviewForm.class);
        reviewForm.setRank(1);

        mockMvc.perform(post("/review/" + review.getId() + "/update")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(reviewForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertEquals(review.getRank(), reviewForm.getRank());
        assertEquals(review.getContent(), reviewForm.getContent());
        assertNotNull(review.getUpdatedDateTime());
        assertEquals(product.getReviewCount(), 1);
        assertEquals(product.getRank(), 1.0);
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("리뷰 수정 - 기간이 지나 수정할 수 없는 경우")
    @Test
    public void updateReview_out_of_date() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Product product = productFactory.createProduct();
        OrderDetails orderDetails = orderFactory.createOrder(product, account).getOrderDetails().get(0);
        Review review = reviewFactory.createReview(account, product, orderDetails);

        int previousRank = review.getRank();
        product.setRank((double) previousRank);
        product.setReviewCount(1);
        review.setCreatedDateTime(LocalDateTime.now().minusMonths(4));

        ReviewForm reviewForm = modelMapper.map(review, ReviewForm.class);
        reviewForm.setRank(1);

        mockMvc.perform(post("/review/" + review.getId() + "/update")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(reviewForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertNull(review.getUpdatedDateTime()); // 리뷰가 수정되지 않음
        assertEquals(product.getRank(), previousRank);
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("리뷰 삭제 - 성공")
    @Test
    public void deleteReview() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Product product = productFactory.createProduct();
        OrderDetails orderDetails = orderFactory.createOrder(product, account).getOrderDetails().get(0);
        Review review = reviewFactory.createReview(account, product, orderDetails);

        account.setMileage((long) review.getEarnedMileage());
        product.setReviewCount(1);
        product.setRank((double) review.getRank());

        mockMvc.perform(post("/review/" + review.getId() + "/delete")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertTrue(review.isDeleted());
        assertEquals(account.getMileage(), 0);
        assertEquals(product.getReviewCount(), 0);
        assertEquals(product.getRank(), 0);
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("상품 이미지 리뷰 정보 가져오기 - 성공")
    @Test
    public void getImageReview() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Product product = productFactory.createProduct();

        List<Review> reviews = new ArrayList<>();
        int idx = 0;
        for (int i = 0; i < 10; i++) { // 10 * 6
            List<OrderDetails> orderDetails = orderFactory.createOrder(product, account).getOrderDetails();
            for (OrderDetails od : orderDetails) {
                Review review = reviewFactory.createReview(account, product, od);
                review.setCreatedDateTime(LocalDateTime.now().plusSeconds(idx++)); // 테스트시 시간이 똑같이 나와서 다르게 만들어줌
                reviews.add(review);
            }
        }

        mockMvc.perform(get("/product/" + product.getId() + "/review/image?page=1")) // 2 페이지 요청
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.currentPage", is(1)))
                .andExpect(jsonPath("$.hasPrevious", is(true)))
                .andExpect(jsonPath("$.hasNext", is(true)))
                .andExpect(jsonPath("$.totalCount", is(60)))
                .andExpect(jsonPath("$.reviewList[*].id", containsInAnyOrder(reviews.subList(20, 40).stream()
                        .map(review -> review.getId().intValue()).collect(Collectors.toList()).toArray())))
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("상품 리뷰 정보 가져오기 - 성공")
    @Test
    public void getReviewContent() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Product product = productFactory.createProduct();

        List<Review> reviews = new ArrayList<>();
        int idx = 0;
        for (int i = 0; i < 20; i++) { // 20 * 6
            List<OrderDetails> orderDetails = orderFactory.createOrder(product, account).getOrderDetails();
            for (OrderDetails od : orderDetails) {
                Review review = reviewFactory.createReview(account, product, od);
                review.setCreatedDateTime(LocalDateTime.now().plusSeconds(idx++));
                reviews.add(review);
            }
        }

        mockMvc.perform(get("/product/" + product.getId() + "/review/content?page=3")) // 4 페이지 요청
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.currentPage", is(3)))
                .andExpect(jsonPath("$.hasPrevious", is(true)))
                .andExpect(jsonPath("$.hasNext", is(true)))
                .andExpect(jsonPath("$.totalCount", is(120)))
                .andExpect(jsonPath("$.startPage", is(0)))
                .andExpect(jsonPath("$.endPage", is(5)))
                .andExpect(jsonPath("$.reviewList[*].id", containsInAnyOrder(reviews.subList(40, 60).stream()
                        .map(review -> review.getId().intValue()).collect(Collectors.toList()).toArray()))) // 최신순이므로 뒤에서 61번째 ~ 80번째
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

}
