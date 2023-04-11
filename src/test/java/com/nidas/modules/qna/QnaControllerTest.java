package com.nidas.modules.qna;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nidas.infra.AbstractContainerBaseTest;
import com.nidas.infra.config.MockMvcTest;
import com.nidas.modules.account.Account;
import com.nidas.modules.account.AccountRepository;
import com.nidas.modules.account.WithAccount;
import com.nidas.modules.product.Product;
import com.nidas.modules.product.ProductFactory;
import com.nidas.modules.qna.form.QnaWriteForm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

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
public class QnaControllerTest extends AbstractContainerBaseTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ProductFactory productFactory;
    @Autowired private QnaFactory qnaFactory;
    @Autowired private AccountRepository accountRepository;
    @Autowired private QnaRepository qnaRepository;
    @Autowired private ObjectMapper objectMapper;

    private final String TEST_EMAIL = "test@email.com";

    @WithAccount(TEST_EMAIL)
    @DisplayName("Q&A 작성 - 성공")
    @Test
    public void writeQna() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Product product = productFactory.createProduct();

        QnaWriteForm qnaWriteForm = new QnaWriteForm();
        qnaWriteForm.setType(QnaType.PRODUCT_QNA);
        qnaWriteForm.setContent("test");
        qnaWriteForm.setSecret(true);

        mockMvc.perform(post("/product/" + product.getId() + "/write/qna")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(qnaWriteForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));
        assertNotNull(qnaRepository.findByAccount(account));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("Q&A 작성 - 존재하지 않는 상품")
    @Test
    public void writeQna_not_exist_product() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);

        QnaWriteForm qnaWriteForm = new QnaWriteForm();
        qnaWriteForm.setType(QnaType.PRODUCT_QNA);
        qnaWriteForm.setContent("test");
        qnaWriteForm.setSecret(true);

        mockMvc.perform(post("/product/1/write/qna")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(qnaWriteForm))
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isNotFound())
                .andExpect(authenticated().withUsername(TEST_EMAIL));
        assertTrue(qnaRepository.findByAccount(account).isEmpty());
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("상품 Q&A정보 가져오기")
    @Test
    public void getQna() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Product product = productFactory.createProduct();

        List<Qna> qnaList = qnaFactory.createQnas(account, product, 50);

        mockMvc.perform(get("/product/" + product.getId() + "/qna?page=2")) // 3 페이지 요청
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.currentPage", is(2)))
                .andExpect(jsonPath("$.hasPrevious", is(true)))
                .andExpect(jsonPath("$.hasNext", is(false)))
                .andExpect(jsonPath("$.totalCount", is(50)))
                .andExpect(jsonPath("$.startPage", is(0)))
                .andExpect(jsonPath("$.endPage", is(2)))
                .andExpect(jsonPath("$.qnaList[*].content", containsInAnyOrder(qnaList.subList(0, 10).stream()
                        .map(qna -> qna.getContent()).collect(Collectors.toList()).toArray()))) // 최신순이므로 뒤에서 41번째 ~ 50번째
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("내 Q&A 목록 페이지 보이는지 확인")
    @Test
    public void getQnaList() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Product product = productFactory.createProduct();

        List<Qna> qnaList = qnaFactory.createQnas(account, product, 10);

        Map<String, Object> model = mockMvc.perform(get("/mypage/qna-list"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("qna/qna-list"))
                .andExpect(model().attributeExists("account", "qnaList"))
                .andExpect(authenticated().withUsername(TEST_EMAIL))
                .andReturn().getModelAndView().getModel();

        List<Qna> qList = (List<Qna>) model.get("qnaList");
        assertEquals(qList.size(), qnaList.size());
        assertTrue(qList.containsAll(qnaList));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("Q&A 삭제 - 성공")
    @Test
    public void deleteQna() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        Product product = productFactory.createProduct();

        Qna qna = qnaFactory.createQna(account, product);

        mockMvc.perform(post("/qna/" + qna.getId() + "/delete")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertTrue(qnaRepository.findById(qna.getId()).isEmpty());
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("Q&A 삭제 - Q&A가 없는 경우")
    @Test
    public void deleteQna_no_qna() throws Exception {
        mockMvc.perform(post("/qna/1/delete")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isNotFound())
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

}
