package com.nidas.modules.cart;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nidas.infra.AbstractContainerBaseTest;
import com.nidas.infra.config.MockMvcTest;
import com.nidas.modules.account.AccountFactory;
import com.nidas.modules.account.AccountRepository;
import com.nidas.modules.account.WithAccount;
import com.nidas.modules.cart.form.CartIdListForm;
import com.nidas.modules.product.Product;
import com.nidas.modules.product.ProductDetails;
import com.nidas.modules.product.ProductFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@MockMvcTest
public class CartControllerTest extends AbstractContainerBaseTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ProductFactory productFactory;
    @Autowired private CartFactory cartFactory;
    @Autowired private AccountFactory accountFactory;
    @Autowired private CartRepository cartRepository;
    @Autowired private AccountRepository accountRepository;
    @Autowired private ObjectMapper objectMapper;

    private final String TEST_EMAIL = "test@email.com";

    @WithAccount(TEST_EMAIL)
    @DisplayName("카트에 물품 추가 - 성공")
    @Test
    public void addCart() throws Exception {
        Product product = productFactory.createProduct();
        String content = "{\"itemList\":[{\"color\":\"BEIGE\",\"size\":\"250\",\"quantity\":\"1\"}," +
                                        "{\"color\":\"BLACK\",\"size\":\"260\",\"quantity\":\"3\"}]}";

        mockMvc.perform(post("/cart/add/product/" + product.getId())
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(content)
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        List<Cart> cartList = cartRepository.findAll();
        assertEquals(cartList.size(), 2);

        Cart cart1 = cartList.get(0);
        assertEquals(cart1.getProductDetails().getColor().name(), "BEIGE");
        assertEquals(cart1.getProductDetails().getSize().getValue(), 250);
        assertEquals(cart1.getQuantity(), 1);

        Cart cart2 = cartList.get(1);
        assertEquals(cart2.getProductDetails().getColor().name(), "BLACK");
        assertEquals(cart2.getProductDetails().getSize().getValue(), 260);
        assertEquals(cart2.getQuantity(), 3);

        // 담긴 물품을 다시 추가하면 덮어쓰게 되는지 확인
        content = "{\"itemList\":[{\"color\":\"BEIGE\",\"size\":\"250\",\"quantity\":\"7\"}]}";

        mockMvc.perform(post("/cart/add/product/" + product.getId())
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(content)
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertEquals(cart1.getProductDetails().getColor().name(), "BEIGE");
        assertEquals(cart1.getProductDetails().getSize().getValue(), 250);
        assertEquals(cart1.getQuantity(), 7);
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("카트에 물품 추가 - 비어있는 물품 목록이 전달된 경우")
    @Test
    public void addCart_with_empty_itemList() throws Exception {
        Product product = productFactory.createProduct();
        String content = "{\"itemList\":[]}";

        mockMvc.perform(post("/cart/add/product/" + product.getId())
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(content)
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertTrue(cartRepository.findAll().isEmpty());
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("카트에 물품 추가 - 잘못된 입력값(색상, 사이즈, 수량)")
    @Test
    public void addCart_with_wrong_input() throws Exception {
        Product product = productFactory.createProduct();
        String content = "{\"itemList\":[{\"color\":\"없는 색상\",\"size\":\"없는 사이즈\",\"quantity\":\"1000\"}]}";

        mockMvc.perform(post("/cart/add/product/" + product.getId())
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(content)
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertTrue(cartRepository.findAll().isEmpty());
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("카트에 물품 추가 - 없는 상품에 접근")
    @Test
    public void addCart_with_no_product() throws Exception {
        String content = "{\"itemList\":[{\"color\":\"BEIGE\",\"size\":\"250\",\"quantity\":\"1\"}]}";

        mockMvc.perform(post("/cart/add/product/1")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(content)
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isNotFound())
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("장바구니 목록 화면 보이는지 테스트")
    @Test
    public void getCartList() throws Exception {
        Product product = productFactory.createProduct();
        List<Cart> carts = cartFactory.createCarts(product, accountRepository.findByEmail(TEST_EMAIL));

        Map<String, Object> model = mockMvc.perform(get("/cart-list"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("cart/cart-list"))
                .andExpect(model().attributeExists("cartList"))
                .andExpect(authenticated().withUsername(TEST_EMAIL))
                .andReturn().getModelAndView().getModel();

        List<Cart> cartList = (List<Cart>) model.get("cartList");
        assertTrue(cartList.containsAll(carts));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("물품 수량 변경 - 성공")
    @Test
    public void updateQuantity() throws Exception {
        Product product = productFactory.createProduct();
        ProductDetails productDetails = product.getDetails().iterator().next();
        Cart cart = cartFactory.createCart(productDetails, accountRepository.findByEmail(TEST_EMAIL));
        String content = "{\"quantity\":\"5\"}";

        mockMvc.perform(post("/cart/" + cart.getId() + "/update/quantity")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(content)
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertEquals(cart.getQuantity(), 5);
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("물품 수량 변경 - 없는 장바구니 물품에 접근")
    @Test
    public void updateQuantity_with_no_id() throws Exception {
        String content = "{\"quantity\":\"1\"}";

        mockMvc.perform(post("/cart/1/update/quantity")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(content)
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isNotFound())
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("물품 수량 변경 - 다른 사람의 장바구니 물품에 접근")
    @Test
    public void updateQuantity_with_no_authority() throws Exception {
        Product product = productFactory.createProduct();
        ProductDetails productDetails = product.getDetails().iterator().next();
        Cart cart = cartFactory.createCart(productDetails, accountFactory.createAccount("test2@email.com"));
        String content = "{\"quantity\":\"5\"}";

        mockMvc.perform(post("/cart/" + cart.getId() + "/update/quantity")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(content)
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isNotFound())
                .andExpect(authenticated().withUsername(TEST_EMAIL));
        assertEquals(cart.getQuantity(), 1); // 바뀌지 않음을 확인
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("물품 삭제 - 성공")
    @Test
    public void removeCart() throws Exception {
        Product product = productFactory.createProduct();
        ProductDetails productDetails = product.getDetails().iterator().next();
        Cart cart = cartFactory.createCart(productDetails, accountRepository.findByEmail(TEST_EMAIL));

        mockMvc.perform(post("/cart/" + cart.getId() + "/remove")
                .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertTrue(cartRepository.findById(cart.getId()).isEmpty());
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("물품 삭제 - 없는 장바구니 물품에 접근")
    @Test
    public void removeCart_with_no_id() throws Exception {
        mockMvc.perform(post("/cart/1/remove")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isNotFound())
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("물품 삭제 - 다른 사람의 장바구니 물품에 접근")
    @Test
    public void removeCart_with_no_authority() throws Exception {
        Product product = productFactory.createProduct();
        ProductDetails productDetails = product.getDetails().iterator().next();
        Cart cart = cartFactory.createCart(productDetails, accountFactory.createAccount("test2@email.com"));

        mockMvc.perform(post("/cart/" + cart.getId() + "/remove")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isNotFound()) // 내 카트에서 다른 사람의 카트 정보를 조회하므로 not found error
                .andExpect(authenticated().withUsername(TEST_EMAIL));
        assertFalse(cartRepository.findById(cart.getId()).isEmpty());
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("물품 목록 삭제 - 성공")
    @Test
    public void removeCartItems() throws Exception {
        Product product = productFactory.createProduct();
        List<Cart> carts = cartFactory.createCarts(product, accountRepository.findByEmail(TEST_EMAIL));

        CartIdListForm cartIdListForm = new CartIdListForm();
        Set<Long> idList = carts.stream().map(cart -> cart.getId()).collect(Collectors.toSet());
        cartIdListForm.setIdList(idList);

        mockMvc.perform(post("/cart/remove")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(cartIdListForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertTrue(cartRepository.findAll().isEmpty());
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("물품 목록 삭제 - 없는 장바구니 물품에 접근")
    @Test
    public void removeCartItems_with_no_id() throws Exception {
        String content = "{\"idList\":[]}";

        mockMvc.perform(post("/cart/remove")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(content)
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("물품 목록 삭제 - 다른 사람의 장바구니 물품에 접근")
    @Test
    public void removeCartItems_with_no_authority() throws Exception {
        Product product = productFactory.createProduct();
        List<Cart> carts = cartFactory.createCarts(product, accountFactory.createAccount("test2@email.com"));

        CartIdListForm cartIdListForm = new CartIdListForm();
        cartIdListForm.setIdList(carts.stream().map(cart -> cart.getId()).collect(Collectors.toSet()));

        mockMvc.perform(post("/cart/remove")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(cartIdListForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isNotFound()) // 내 카트에서 다른 사람의 카트 정보를 조회하므로 not found error
                .andExpect(authenticated().withUsername(TEST_EMAIL));
        assertFalse(cartRepository.findAll().isEmpty());
    }

}
