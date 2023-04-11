package com.nidas.modules.favorites;

import com.nidas.infra.AbstractContainerBaseTest;
import com.nidas.infra.config.MockMvcTest;
import com.nidas.modules.account.Account;
import com.nidas.modules.account.AccountRepository;
import com.nidas.modules.account.WithAccount;
import com.nidas.modules.product.Product;
import com.nidas.modules.product.ProductFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@MockMvcTest
public class FavoritesControllerTest extends AbstractContainerBaseTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ProductFactory productFactory;
    @Autowired private AccountRepository accountRepository;
    @Autowired private FavoritesRepository favoritesRepository;

    private final String TEST_EMAIL = "test@email.com";

    @WithAccount(TEST_EMAIL)
    @DisplayName("즐겨찾기 목록 화면 보이는지 테스트")
    @Test
    public void getFavoritesList() throws Exception {
        mockMvc.perform(get("/mypage/favorites-list"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("favorites/favorites-list"))
                .andExpect(model().attributeExists("account", "favoritesProductList"))
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("즐겨찾기 등록")
    @Test
    public void addFavorites() throws Exception {
        Product product = productFactory.createProduct();
        Account account = accountRepository.findByEmail(TEST_EMAIL);

        mockMvc.perform(post("/favorites/product/" + product.getId() + "/add")
                .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertEquals(product.getFavoritesCount(), 1); // 상품의 즐겨찾기 수 1증가
        assertNotNull(favoritesRepository.findByAccountAndProduct(account, product)); // 해당 계정의 상품에 대한 즐겨찾기가 등록됨을 확인
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("즐겨찾기 등록 - 없는 상품에 접근")
    @Test
    public void addFavorites_no_product() throws Exception {
        mockMvc.perform(post("/favorites/product/1/add")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isNotFound())
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("즐겨찾기 삭제")
    @Test
    public void removeFavorites() throws Exception {
        Product product = productFactory.createProduct();
        Account account = accountRepository.findByEmail(TEST_EMAIL);

        Favorites favorites = favoritesRepository.save(Favorites.builder().account(account).product(product).build());
        assertNotNull(favorites);
        product.setFavoritesCount(1);

        mockMvc.perform(post("/favorites/product/" + product.getId() + "/remove")
                .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertEquals(product.getFavoritesCount(), 0); // 상품의 즐겨찾기 수 1감소
        assertNull(favoritesRepository.findByAccountAndProduct(account, product)); // 해당 계정의 상품에 대한 즐겨찾기가 삭제됨을 확인
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("즐겨찾기 삭제 - 없는 상품에 접근")
    @Test
    public void removeFavorites_no_product() throws Exception {
        mockMvc.perform(post("/favorites/product/1/remove")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isNotFound())
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }
}
