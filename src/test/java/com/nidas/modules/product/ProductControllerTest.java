package com.nidas.modules.product;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nidas.infra.AbstractContainerBaseTest;
import com.nidas.infra.config.MockMvcTest;
import com.nidas.infra.exception.ResourceNotFoundException;
import com.nidas.modules.account.Authority;
import com.nidas.modules.account.WithAccount;
import com.nidas.modules.product.form.ProductDetailsForm;
import com.nidas.modules.product.form.ProductForm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.NestedServletException;

import java.time.LocalDateTime;
import java.util.ArrayList;
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
public class ProductControllerTest extends AbstractContainerBaseTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ProductRepository productRepository;
    @Autowired private ProductFactory productFactory;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private ModelMapper modelMapper;

    private final String TEST_EMAIL = "test@email.com";

    @BeforeEach
    public void setup() {
        objectMapper.setVisibility(objectMapper.getSerializationConfig().getDefaultVisibilityChecker()
                .withFieldVisibility(JsonAutoDetect.Visibility.ANY)
                .withGetterVisibility(JsonAutoDetect.Visibility.NONE)
                .withSetterVisibility(JsonAutoDetect.Visibility.NONE)
                .withCreatorVisibility(JsonAutoDetect.Visibility.NONE));
    }

    @WithAccount(value = TEST_EMAIL, authority = Authority.ROLE_ADMIN)
    @DisplayName("상품 관리 화면 보이는지 테스트")
    @Test
    public void getProductList() throws Exception {
        List<Product> productList = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            Product product = productFactory.createProduct();
            product.setCreatedDateTime(LocalDateTime.now().plusSeconds(i));
            productList.add(product);
        }
        Map<String, Object> model = mockMvc.perform(get("/admin/management/product")
                    .param("page", "2") // 3 page
                    .param("keywords", "상품명")
                    .param("discount", "false")
                    .param("soldOut", "false")
                    .param("recent", "false")
                    .param("color", "BEIGE")
                    .param("sorting", Sorting.OLD.name())) // 생성시간 오름차순
                    .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("product/admin/product-management"))
                .andExpect(model().attributeExists("productPage", "adminProductSearchForm"))
                .andExpect(authenticated().withUsername(TEST_EMAIL).withAuthorities(List.of(new SimpleGrantedAuthority(Authority.ROLE_ADMIN.toString()))))
                .andReturn().getModelAndView().getModel();

        Page<Product> productPage = (Page<Product>) model.get("productPage");
        assertEquals(productPage.getTotalElements(), 100); // 전체 요소 개수
        assertEquals(productPage.getTotalPages(), 5); // 총 페이지
        assertEquals(productPage.getNumber(), 2); // 현재 페이지
        assertEquals(productPage.getNumberOfElements(), 20); // 현재 페이지 요소 개수
        assertTrue(productPage.getContent().containsAll(productList.subList(40, 60))); // 41번째 ~ 60번째
    }

    @WithAccount(value = TEST_EMAIL, authority = Authority.ROLE_ADMIN)
    @DisplayName("상품 추가 화면 보이는지 테스트")
    @Test
    public void createProductForm() throws Exception {
        mockMvc.perform(get("/admin/management/product/create"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("product/admin/create-product"))
                .andExpect(model().attributeExists("colorList", "productForm"))
                .andExpect(authenticated().withUsername(TEST_EMAIL).withAuthorities(List.of(new SimpleGrantedAuthority(Authority.ROLE_ADMIN.toString()))));
    }

    @WithAccount(value = TEST_EMAIL, authority = Authority.ROLE_ADMIN)
    @DisplayName("상품 추가 처리 - 성공")
    @Test
    public void createProduct() throws Exception {
        ProductDetailsForm productDetailsForm1 = createProductDetailsForm(Color.BEIGE, Size.TWO_HUNDRED_FIFTY);
        ProductDetailsForm productDetailsForm2 = createProductDetailsForm(Color.BLACK, Size.TWO_HUNDRED_FIFTY);
        ProductForm productForm = createProductForm(List.of(productDetailsForm1, productDetailsForm2));

        String content = objectMapper.writeValueAsString(productForm).replaceAll("\"size\":\"TWO_HUNDRED_FIFTY\"", "\"size\":\"250\"");
        mockMvc.perform(post("/admin/management/product/create")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(content)
                    .with(csrf()))
                    .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL).withAuthorities(List.of(new SimpleGrantedAuthority(Authority.ROLE_ADMIN.toString()))));

        Product product = productRepository.findAll().get(0);
        assertNotNull(product);
        assertEquals(product.getName(), productForm.getName());
        assertEquals(product.getThumbnail(), null);
        assertEquals(product.getDetails().size(), 2);
    }

    @WithAccount(value = TEST_EMAIL, authority = Authority.ROLE_ADMIN)
    @DisplayName("상품 추가 처리 - 잘못된 입력값(색상, 사이즈)")
    @Test
    public void createProduct_with_wrong_input() throws Exception {
        ProductDetailsForm productDetailsForm = createProductDetailsForm(null, null);
        ProductForm productForm = createProductForm(List.of(productDetailsForm));

        mockMvc.perform(post("/admin/management/product/create")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(productForm))
                    .with(csrf()))
                    .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL).withAuthorities(List.of(new SimpleGrantedAuthority(Authority.ROLE_ADMIN.toString()))));

        assertTrue(productRepository.findAll().isEmpty());
    }

    @WithAccount(value = TEST_EMAIL, authority = Authority.ROLE_ADMIN)
    @DisplayName("상품 수정 화면 보이는지 테스트")
    @Test
    public void updateProductForm() throws Exception {
        Product product = productFactory.createProduct();
        mockMvc.perform(get("/admin/management/product/" + product.getId() + "/update"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("product/admin/update-product"))
                .andExpect(model().attributeExists("id", "productForm", "colorList"))
                .andExpect(authenticated().withUsername(TEST_EMAIL).withAuthorities(List.of(new SimpleGrantedAuthority(Authority.ROLE_ADMIN.toString()))));
    }

    @WithAccount(value = TEST_EMAIL, authority = Authority.ROLE_ADMIN)
    @DisplayName("상품 수정 화면 보이는지 테스트 - 없는 상품에 접근")
    @Test
    public void updateProductForm_no_id() throws Exception {
        NestedServletException exception = assertThrows(NestedServletException.class, () -> {
            mockMvc.perform(get("/admin/management/product/1/update"))
                    .andDo(print())
                    .andExpect(authenticated().withUsername(TEST_EMAIL).withAuthorities(List.of(new SimpleGrantedAuthority(Authority.ROLE_ADMIN.toString()))));
        });
        assertTrue(ResourceNotFoundException.class.isInstance(exception.getCause()));
    }

    @WithAccount(value = TEST_EMAIL, authority = Authority.ROLE_ADMIN)
    @DisplayName("상품 수정 처리 - 성공")
    @Test
    public void updateProduct() throws Exception {
        Product product = productFactory.createProduct();
        ProductForm productForm = modelMapper.map(product, ProductForm.class);

        ProductDetailsForm productDetailsForm = createProductDetailsForm(Color.BLUE, Size.TWO_HUNDRED_SIXTY);
        productForm.setName("updated");
        productForm.setDetails(List.of(productDetailsForm));

        String content = objectMapper.writeValueAsString(productForm).replaceAll("\"size\":\"TWO_HUNDRED_SIXTY\"", "\"size\":\"260\"");
        mockMvc.perform(post("/admin/management/product/" + product.getId() + "/update")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(content)
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL).withAuthorities(List.of(new SimpleGrantedAuthority(Authority.ROLE_ADMIN.toString()))));

        Product updatedProduct = productRepository.findByIdAndDeletedFalse(product.getId());
        assertEquals(updatedProduct.getName(), productForm.getName());
        assertEquals(updatedProduct.getDetails().size(), 1);
        ProductDetails pd1 = updatedProduct.getDetails().iterator().next();
        ProductDetailsForm pd2 = productForm.getDetails().get(0);
        assertEquals(pd1.getColor(), pd2.getColor());
        assertEquals(pd1.getSize(), pd2.getSize());
        assertEquals(pd1.getStock(), pd2.getStock());
    }

    @WithAccount(value = TEST_EMAIL, authority = Authority.ROLE_ADMIN)
    @DisplayName("상품 수정 처리 - 없는 상품에 접근")
    @Test
    public void updateProduct_no_id() throws Exception {
        Product product = productFactory.createProduct();
        ProductForm productForm = modelMapper.map(product, ProductForm.class);

        ProductDetailsForm productDetailsForm = createProductDetailsForm(Color.BLUE, Size.TWO_HUNDRED_SIXTY);
        productForm.setName("updated");
        productForm.setDetails(List.of(productDetailsForm));

        String content = objectMapper.writeValueAsString(productForm).replaceAll("\"size\":\"TWO_HUNDRED_SIXTY\"", "\"size\":\"260\"");
        mockMvc.perform(post("/admin/management/product/" + (product.getId() + 1) + "/update")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(content)
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isNotFound())
                .andExpect(authenticated().withUsername(TEST_EMAIL).withAuthorities(List.of(new SimpleGrantedAuthority(Authority.ROLE_ADMIN.toString()))));
    }

    @WithAccount(value = TEST_EMAIL, authority = Authority.ROLE_ADMIN)
    @DisplayName("상품 수정 처리 - 잘못된 입력값(카테고리, 이름)")
    @Test
    public void updateProduct_with_wrong_input() throws Exception {
        Product product = productFactory.createProduct();
        ProductForm productForm = modelMapper.map(product, ProductForm.class);

        ProductDetailsForm productDetailsForm = createProductDetailsForm(Color.BLUE, Size.TWO_HUNDRED_SIXTY);
        productForm.setName(null);
        productForm.setMainCategory(null);
        productForm.setSubCategory(null);
        productForm.setDetails(List.of(productDetailsForm));

        String content = objectMapper.writeValueAsString(productForm).replaceAll("\"size\":\"TWO_HUNDRED_SIXTY\"", "\"size\":\"260\"");
        mockMvc.perform(post("/admin/management/product/" + product.getId() + "/update")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(content)
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL).withAuthorities(List.of(new SimpleGrantedAuthority(Authority.ROLE_ADMIN.toString()))));

        assertNotEquals(product.getName(), productForm.getName()); // 변경되지 않음을 확인
        assertNotEquals(product.getMainCategory(), productForm.getMainCategory());
        assertNotEquals(product.getSubCategory(), productForm.getSubCategory());
    }

    private ProductDetailsForm createProductDetailsForm(Color color, Size size) {
        ProductDetailsForm productDetailsForm = new ProductDetailsForm();
        productDetailsForm.setColor(color);
        productDetailsForm.setSize(size);
        productDetailsForm.setStock(100);
        return productDetailsForm;
    }

    private ProductForm createProductForm(List<ProductDetailsForm> details) {
        ProductForm productForm = new ProductForm();
        productForm.setMainCategory(MainCategory.MEN);
        productForm.setSubCategory(SubCategory.LIFESTYLE);
        productForm.setName("test");
        productForm.setPrice(50000);
        productForm.setDiscountRate(0);
        productForm.setMaterial("원료");
        productForm.setMadeIn("생산지");
        productForm.setWashing("세탁법");
        productForm.setDescription("상세내용");
        productForm.setDetails(details);
        return productForm;
    }

    @WithAccount(value = TEST_EMAIL, authority = Authority.ROLE_ADMIN)
    @DisplayName("상품 삭제 처리 - 성공")
    @Test
    public void deleteProduct() throws Exception {
        Product product = productFactory.createProduct();

        assertFalse(product.isDeleted());
        mockMvc.perform(post("/admin/management/product/" + product.getId() + "/delete")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL).withAuthorities(List.of(new SimpleGrantedAuthority(Authority.ROLE_ADMIN.toString()))));
        assertTrue(product.isDeleted());
    }

    @WithAccount(value = TEST_EMAIL, authority = Authority.ROLE_ADMIN)
    @DisplayName("상품 삭제 처리 - 없는 상품에 접근")
    @Test
    public void deleteProduct_no_id() throws Exception {
        mockMvc.perform(post("/admin/management/product/1/delete")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isNotFound())
                .andExpect(authenticated().withUsername(TEST_EMAIL).withAuthorities(List.of(new SimpleGrantedAuthority(Authority.ROLE_ADMIN.toString()))));
    }

    @WithAccount(value = TEST_EMAIL, authority = Authority.ROLE_ADMIN)
    @DisplayName("상품 복구 처리 화면 보이는지 테스트")
    @Test
    public void restoreProductForm() throws Exception {
        List<Product> productList = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            Product product = productFactory.createProduct();
            product.setDeleted(true); // 상품 삭제
            productList.add(product);
        }

        Map<String, Object> model = mockMvc.perform(get("/admin/management/product/restore")
                .param("keywords", "상품명"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("product/admin/restore-product"))
                .andExpect(model().attributeExists("keywords", "productPage"))
                .andExpect(authenticated().withUsername(TEST_EMAIL).withAuthorities(List.of(new SimpleGrantedAuthority(Authority.ROLE_ADMIN.toString()))))
                .andReturn().getModelAndView().getModel();

        Page<Product> productPage = (Page<Product>) model.get("productPage");
        assertTrue(productPage.getContent().containsAll(productList));
    }

    @WithAccount(value = TEST_EMAIL, authority = Authority.ROLE_ADMIN)
    @DisplayName("상품 복구 처리 - 성공")
    @Test
    public void restoreProduct() throws Exception {
        Product product = productFactory.createProduct();
        product.setDeleted(true);

        assertTrue(product.isDeleted());
        mockMvc.perform(post("/admin/management/product/" + product.getId() + "/restore")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL).withAuthorities(List.of(new SimpleGrantedAuthority(Authority.ROLE_ADMIN.toString()))));
        assertFalse(product.isDeleted());
    }

    @WithAccount(value = TEST_EMAIL, authority = Authority.ROLE_ADMIN)
    @DisplayName("상품 복구 처리 - 없는 상품에 접근")
    @Test
    public void restoreProduct_no_id() throws Exception {
        mockMvc.perform(post("/admin/management/product/1/restore")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isNotFound())
                .andExpect(authenticated().withUsername(TEST_EMAIL).withAuthorities(List.of(new SimpleGrantedAuthority(Authority.ROLE_ADMIN.toString()))));
    }

    @WithAccount(value = TEST_EMAIL, authority = Authority.ROLE_ADMIN)
    @DisplayName("상품 조회")
    @Test
    public void searchProducts() throws Exception {
        List<Product> productList = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            Product product = productFactory.createProduct();
            product.setCreatedDateTime(LocalDateTime.now().plusSeconds(i));
            productList.add(product);
        }
        Map<String, Object> model = mockMvc.perform(get("/products")
                    .param("page", "2") // 3 page
                    .param("keywords", "상품명")
                    .param("mainCategory", MainCategory.MEN.name())
                    .param("subCategory", SubCategory.LIFESTYLE.getName())
                    .param("discount", "false")
                    .param("exceptSoldOut", "true")
                    .param("recent", "true")
                    .param("minPrice", "10000")
                    .param("maxPrice", "50000")
                    .param("color", Color.BEIGE.name())
                    .param("sorting", Sorting.OLD.name())) // 생성시간 오름차순
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("product/product-list"))
                .andExpect(model().attributeExists("productSearchForm", "productPage"))
                .andExpect(authenticated().withUsername(TEST_EMAIL).withAuthorities(List.of(new SimpleGrantedAuthority(Authority.ROLE_ADMIN.toString()))))
                .andReturn().getModelAndView().getModel();

        Page<Product> productPage = (Page<Product>) model.get("productPage");
        assertEquals(productPage.getTotalElements(), 100); // 전체 요소 개수
        assertEquals(productPage.getTotalPages(), 5); // 총 페이지
        assertEquals(productPage.getNumber(), 2); // 현재 페이지
        assertEquals(productPage.getNumberOfElements(), 20); // 현재 페이지 요소 개수
        assertTrue(productPage.getContent().containsAll(productList.subList(40, 60))); // 41번째 ~ 60번째
    }

    @WithAccount(value = TEST_EMAIL, authority = Authority.ROLE_ADMIN)
    @DisplayName("상품 조회 - 없는 카테고리에 접근")
    @Test
    public void searchProducts_with_no_category() throws Exception {
        productFactory.createProduct();
        mockMvc.perform(get("/products")
                    .param("page", "0")
                    .param("keywords", "상품명")
                    .param("mainCategory", "없는 메인 카테고리")
                    .param("subCategory", "없는 서브 카테고리")
                    .param("discount", "false")
                    .param("exceptSoldOut", "true")
                    .param("recent", "true")
                    .param("minPrice", "10000")
                    .param("maxPrice", "50000")
                    .param("color", Color.BEIGE.name())
                    .param("sorting", Sorting.OLD.name())) // 생성시간 오름차순
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("product/product-list"))
                .andExpect(model().attributeExists("productSearchForm", "productPage"))
                .andExpect(model().attribute("productPage", Page.empty()))
                .andExpect(authenticated().withUsername(TEST_EMAIL).withAuthorities(List.of(new SimpleGrantedAuthority(Authority.ROLE_ADMIN.toString()))));
    }

    @WithAccount(value = TEST_EMAIL, authority = Authority.ROLE_ADMIN)
    @DisplayName("상품 상세 조회")
    @Test
    public void getProductDetails() throws Exception {
        Product product = productFactory.createProduct();
        mockMvc.perform(get("/product/" + product.getId()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("product/product-details"))
                .andExpect(model().attributeExists("product", "minQuantity", "maxQuantity"))
                .andExpect(model().attribute("product", product))
                .andExpect(authenticated().withUsername(TEST_EMAIL).withAuthorities(List.of(new SimpleGrantedAuthority(Authority.ROLE_ADMIN.toString()))));
    }

    @WithAccount(value = TEST_EMAIL, authority = Authority.ROLE_ADMIN)
    @DisplayName("상품 상세 조회 - 없는 상품에 접근")
    @Test
    public void getProductDetails_no_id() throws Exception {
        NestedServletException exception = assertThrows(NestedServletException.class, () -> {
            mockMvc.perform(get("/product/1"))
                    .andDo(print())
                    .andExpect(authenticated().withUsername(TEST_EMAIL).withAuthorities(List.of(new SimpleGrantedAuthority(Authority.ROLE_ADMIN.toString()))));
        });
        assertTrue(ResourceNotFoundException.class.isInstance(exception.getCause()));
    }

}
