package com.nidas.modules.account;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nidas.infra.AbstractContainerBaseTest;
import com.nidas.infra.config.MockMvcTest;
import com.nidas.infra.config.TestProperties;
import com.nidas.infra.mail.EmailMessage;
import com.nidas.infra.mail.EmailService;
import com.nidas.modules.account.form.DetailsForm;
import com.nidas.modules.account.form.PasswordForm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.times;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@MockMvcTest
public class AccountControllerTest extends AbstractContainerBaseTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private AccountRepository accountRepository;
    @Autowired private TestProperties testProperties;
    @Autowired private AccountFactory accountFactory;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private PasswordEncoder passwordEncoder;

    @MockBean EmailService emailService;

    private final String TEST_EMAIL = "test@email.com";

    @DisplayName("회원가입 화면 보이는지 테스트")
    @Test
    public void signUpForm() throws Exception {
        mockMvc.perform(get("/sign-up"))
                    .andDo(print())
                    .andExpect(status().isOk())
                    .andExpect(view().name("account/sign-up"))
                .andExpect(model().attributeExists("signUpForm"))
                .andExpect(unauthenticated());
    }

    @DisplayName("회원가입 처리 - 성공")
    @Test
    public void signUp() throws Exception {
        mockMvc.perform(post("/sign-up")
                    .param("email", testProperties.getEmail())
                    .param("password1", testProperties.getPassword())
                    .param("password2", testProperties.getPassword())
                    .param("name", testProperties.getName())
                    .param("gender", testProperties.getGender())
                    .param("birthday", testProperties.getBirthday())
                    .param("phoneNumber", testProperties.getPhoneNumber())
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/"))
                .andExpect(authenticated().withUsername(testProperties.getEmail()));

        Account account = accountRepository.findByEmail(testProperties.getEmail());
        assertNotNull(account);
        assertNotEquals(account.getPassword(), testProperties.getPassword()); // 패스워드 인코딩 확인
        assertNotNull(account.getEmailCheckToken()); // 이메일 토큰 생성 확인
        then(emailService).should(times(1)).sendEmail(any(EmailMessage.class)); // 이메일 보내는지 확인
    }

    @DisplayName("회원가입 처리 - 잘못된 입력값(중복된 이메일)")
    @Test
    public void signUp_with_wrong_input_1() throws Exception {
        accountFactory.createAccount(testProperties.getEmail());
        mockMvc.perform(post("/sign-up")
                    .param("email", testProperties.getEmail())
                    .param("password1", testProperties.getPassword())
                    .param("password2", testProperties.getPassword())
                    .param("name", testProperties.getName())
                    .param("gender", testProperties.getGender())
                    .param("birthday", testProperties.getBirthday())
                    .param("phoneNumber", testProperties.getPhoneNumber())
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("account/sign-up"))
                .andExpect(model().hasErrors())
                .andExpect(unauthenticated());

        then(emailService).shouldHaveNoMoreInteractions(); // 이메일을 보내지 않음을 확인
    }

    @DisplayName("회원가입 처리 - 잘못된 입력값(비밀번호 다름)")
    @Test
    public void signUp_with_wrong_input_2() throws Exception {
        mockMvc.perform(post("/sign-up")
                    .param("email", testProperties.getEmail())
                    .param("password1", testProperties.getPassword())
                    .param("password2", "1234abcd!")
                    .param("name", testProperties.getName())
                    .param("gender", testProperties.getGender())
                    .param("birthday", testProperties.getBirthday())
                    .param("phoneNumber", testProperties.getPhoneNumber())
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("account/sign-up"))
                .andExpect(model().hasErrors())
                .andExpect(unauthenticated());

        assertNull(accountRepository.findByEmail(testProperties.getEmail()));
        then(emailService).shouldHaveNoMoreInteractions(); // 이메일을 보내지 않음을 확인
    }

    @DisplayName("회원가입 처리 - 잘못된 입력값(잘못된 성별값)")
    @Test
    public void signUp_with_wrong_input_3() throws Exception {
        mockMvc.perform(post("/sign-up")
                    .param("email", testProperties.getEmail())
                    .param("password1", testProperties.getPassword())
                    .param("password2", testProperties.getPassword())
                    .param("name", testProperties.getName())
                    .param("gender", "S")
                    .param("birthday", testProperties.getBirthday())
                    .param("phoneNumber", testProperties.getPhoneNumber())
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("account/sign-up"))
                .andExpect(model().hasErrors())
                .andExpect(unauthenticated());

        assertNull(accountRepository.findByEmail(testProperties.getEmail()));
        then(emailService).shouldHaveNoMoreInteractions(); // 이메일을 보내지 않음을 확인
    }

    @DisplayName("회원가입 처리 - 잘못된 입력값(잘못된 생일값)")
    @Test
    public void signUp_with_wrong_input_4() throws Exception {
        mockMvc.perform(post("/sign-up")
                    .param("email", testProperties.getEmail())
                    .param("password1", testProperties.getPassword())
                    .param("password2", testProperties.getPassword())
                    .param("name", testProperties.getName())
                    .param("gender", testProperties.getGender())
                    .param("birthday", "19800132")
                    .param("phoneNumber", testProperties.getPhoneNumber())
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("account/sign-up"))
                .andExpect(model().hasErrors())
                .andExpect(unauthenticated());

        assertNull(accountRepository.findByEmail(testProperties.getEmail()));
        then(emailService).shouldHaveNoMoreInteractions(); // 이메일을 보내지 않음을 확인
    }

    @Test
    @DisplayName("이메일 인증 확인 처리 - 성공")
    void checkEmailToken() throws Exception {
        Account account = accountFactory.createAccount(testProperties.getEmail());
        mockMvc.perform(get("/check-email-token")
                    .param("email", account.getEmail())
                    .param("token", account.getEmailCheckToken()))
                .andExpect(status().isOk())
                .andExpect(view().name("account/checked-email"))
                .andExpect(model().attributeExists("successMessage"))
                .andExpect(authenticated().withUsername(account.getEmail()));

        assertTrue(account.isEmailVerified()); // 인증된 상태로 바뀌는지 확인
    }

    @Test
    @DisplayName("이메일 인증 처리 - 잘못된 입력값(존재하지 않는 이메일)")
    void validateEmailToken_with_wrong_value_1() throws Exception {
        mockMvc.perform(get("/check-email-token")
                    .param("email", testProperties.getEmail())
                    .param("token", "token123"))
                .andExpect(status().isOk())
                .andExpect(view().name("account/checked-email"))
                .andExpect(model().attributeExists("errorMessage"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("이메일 인증 처리 - 잘못된 입력값(유효하지 않은 토큰)")
    void validateEmailToken_with_wrong_value_2() throws Exception {
        Account account = accountFactory.createAccount(testProperties.getEmail());
        mockMvc.perform(get("/check-email-token")
                    .param("email", account.getEmail())
                    .param("token", account.getEmailCheckToken() + "diff"))
                .andExpect(status().isOk())
                .andExpect(view().name("account/checked-email"))
                .andExpect(model().attributeExists("errorMessage"))
                .andExpect(unauthenticated());
    }

    @DisplayName("로그인 화면 보이는지 테스트")
    @Test
    public void login() throws Exception {
        mockMvc.perform(get("/login"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("account/login"))
                .andExpect(unauthenticated());
    }

    @DisplayName("비밀번호 찾기 화면 보이는지 테스트")
    @Test
    public void findPasswordForm() throws Exception {
        mockMvc.perform(get("/find-password"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("account/find-password"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("비밀번호 찾기 처리 - 성공")
    void findPassword() throws Exception {
        Account account = accountFactory.createAccount(testProperties.getEmail());
        mockMvc.perform(post("/find-password")
                    .param("email", account.getEmail())
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/find-password"))
                .andExpect(flash().attributeExists("successMessage"))
                .andExpect(unauthenticated());

        assertNotNull(account.getPasswordFindToken()); // 비밀번호 찾기용 이메일 토큰 생성 확인
        then(emailService).should(times(1)).sendEmail(any(EmailMessage.class)); // 이메일 보내는지 확인
    }

    @Test
    @DisplayName("비밀번호 찾기 처리 - 잘못된 입력값(존재하지 않는 이메일)")
    void findPassword_with_wrong_value_1() throws Exception {
        mockMvc.perform(post("/find-password")
                    .param("email", testProperties.getEmail())
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("account/find-password"))
                .andExpect(model().attributeExists("errorMessage"))
                .andExpect(unauthenticated());

        then(emailService).shouldHaveNoMoreInteractions(); // 이메일을 보내지 않음을 확인
    }

    @Test
    @DisplayName("비밀번호 찾기 처리 - 잘못된 입력값(이메일 쿨타임)")
    void findPassword_with_wrong_value_2() throws Exception {
        Account account = accountFactory.createAccount(testProperties.getEmail());
        account.generatePasswordFindToken(); // 요청 전 비밀번호 찾기용 토큰 생성

        mockMvc.perform(post("/find-password")
                    .param("email", account.getEmail())
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("account/find-password"))
                .andExpect(model().attributeExists("errorMessage"))
                .andExpect(unauthenticated());

        then(emailService).shouldHaveNoMoreInteractions(); // 이메일을 보내지 않음을 확인
    }

    @Test
    @DisplayName("비밀번호 찾기 인증 처리 - 성공")
    void checkPasswordFindToken() throws Exception {
        Account account = accountFactory.createAccount(testProperties.getEmail());
        account.generatePasswordFindToken();

        mockMvc.perform(get("/check-password-find-token")
                    .param("email", account.getEmail())
                    .param("token", account.getPasswordFindToken()))
                .andExpect(status().isOk())
                .andExpect(view().name("account/checked-email"))
                .andExpect(model().attributeExists("successMessage"))
                .andExpect(authenticated().withUsername(account.getEmail())); // 로그인 상태로 변경

        assertNull(account.getPasswordFindToken()); // 확인 후 비밀번호 찾기용 토큰은 삭제
    }

    @Test
    @DisplayName("비밀번호 찾기 인증 처리 - 잘못된 입력값(존재하지 않는 이메일)")
    void checkPasswordFindToken_with_wrong_value_1() throws Exception {
        mockMvc.perform(get("/check-password-find-token")
                    .param("email", testProperties.getEmail())
                    .param("token", "token123"))
                .andExpect(status().isOk())
                .andExpect(view().name("account/checked-email"))
                .andExpect(model().attributeExists("errorMessage"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("비밀번호 찾기 인증 처리 - 잘못된 입력값(유효하지 않은 토큰)")
    void checkPasswordFindToken_with_wrong_value_2() throws Exception {
        Account account = accountFactory.createAccount(testProperties.getEmail());
        account.generatePasswordFindToken();

        mockMvc.perform(get("/check-password-find-token")
                    .param("email", account.getEmail())
                    .param("token", account.getPasswordFindToken() + "diff"))
                .andExpect(status().isOk())
                .andExpect(view().name("account/checked-email"))
                .andExpect(model().attributeExists("errorMessage"))
                .andExpect(unauthenticated());
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("정보 수정 화면 보이는지 테스트")
    @Test
    public void editInfoForm() throws Exception {
        mockMvc.perform(get("/mypage/edit/info"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("account/edit-info"))
                .andExpect(model().attributeExists("account", "detailsForm", "passwordForm"))
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    @WithAccount(TEST_EMAIL)
    @Test
    @DisplayName("이메일 재전송 처리 - 성공")
    void resendVerificationCode() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        account.setEmailCheckTokenGeneratedDateTime(LocalDateTime.now().minusHours(2));
        account.setEmailVerified(false);

        mockMvc.perform(post("/resend/verification-code")
                .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        then(emailService).should(times(2)).sendEmail(any(EmailMessage.class)); // 이메일 보내는지 확인
    }

    @WithAccount(TEST_EMAIL)
    @Test
    @DisplayName("이메일 재전송 처리 - 잘못된 입력값(이미 인증된 상태)")
    void resendVerificationCode_with_wrong_value_1() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        account.setEmailCheckTokenGeneratedDateTime(LocalDateTime.now().minusHours(2));
        account.setEmailVerified(true);

        String content = mockMvc.perform(post("/resend/verification-code")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL)).andReturn().getResponse().getContentAsString();

        assertTrue(content.contains("message"));
        then(emailService).should(times(1)).sendEmail(any(EmailMessage.class)); // 이메일을 보내지 않음을 확인
    }

    @WithAccount(TEST_EMAIL)
    @Test
    @DisplayName("이메일 재전송 처리 - 잘못된 입력값(이메일 쿨타임)")
    void resendVerificationCode_with_wrong_value_2() throws Exception {
        // test security context 설정 시에 이메일을 보내고 쿨타임인 상태로 요청을 보냄
        String content = mockMvc.perform(post("/resend/verification-code")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL)).andReturn().getResponse().getContentAsString();

        assertTrue(content.contains("message"));
        then(emailService).should(times(1)).sendEmail(any(EmailMessage.class)); // 이메일을 보내지 않음을 확인
    }

    @WithAccount(TEST_EMAIL)
    @Test
    @DisplayName("개인 정보 변경 처리 - 성공")
    void editDetailsInfo() throws Exception {
        DetailsForm detailsForm = new DetailsForm();
        detailsForm.setName("김민수");
        detailsForm.setGender(Gender.U);
        detailsForm.setBirthday(LocalDate.parse("1990-03-31", DateTimeFormatter.ofPattern("yyyy-MM-dd")));
        detailsForm.setPhoneNumber("01087654321");

        String requestBody = objectMapper.writeValueAsString(detailsForm);
        mockMvc.perform(post("/mypage/edit/info/details")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(requestBody)
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        Account account = accountRepository.findByEmail(TEST_EMAIL);
        assertEquals(account.getName(), detailsForm.getName());
        assertEquals(account.getGender(), detailsForm.getGender());
        assertEquals(account.getBirthday(), detailsForm.getBirthday());
        assertEquals(account.getPhoneNumber(), detailsForm.getPhoneNumber());
    }

    @WithAccount(TEST_EMAIL)
    @Test
    @DisplayName("개인 정보 변경 처리 - 잘못된 입력값")
    void editDetailsInfo_with_wrong_value() throws Exception {
        DetailsForm detailsForm = new DetailsForm();
        detailsForm.setName("123");
        detailsForm.setGender(null);
        detailsForm.setBirthday(LocalDate.parse("1800-03-31", DateTimeFormatter.ofPattern("yyyy-MM-dd")));
        detailsForm.setPhoneNumber("12345");

        String requestBody = objectMapper.writeValueAsString(detailsForm);
        mockMvc.perform(post("/mypage/edit/info/details")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(requestBody)
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    @WithAccount(TEST_EMAIL)
    @Test
    @DisplayName("로그인 정보 변경 처리 - 성공")
    void editPasswordsInfo() throws Exception {
        PasswordForm passwordForm = new PasswordForm();
        passwordForm.setCurrentPassword(testProperties.getPassword());
        passwordForm.setNewPassword1(testProperties.getPassword() + "new");
        passwordForm.setNewPassword2(testProperties.getPassword() + "new");

        String requestBody = objectMapper.writeValueAsString(passwordForm);
        mockMvc.perform(post("/mypage/edit/info/password")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(requestBody)
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        Account account = accountRepository.findByEmail(TEST_EMAIL);
        assertTrue(passwordEncoder.matches(passwordForm.getNewPassword1(), account.getPassword()));
    }

    @WithAccount(TEST_EMAIL)
    @Test
    @DisplayName("로그인 정보 변경 처리 - 비밀번호 틀림")
    void editPasswordsInfo_with_wrong_value_1() throws Exception {
        PasswordForm passwordForm = new PasswordForm();
        passwordForm.setCurrentPassword(testProperties.getPassword() + "wrong");
        passwordForm.setNewPassword1(testProperties.getPassword() + "new");
        passwordForm.setNewPassword2(testProperties.getPassword() + "new");

        String requestBody = objectMapper.writeValueAsString(passwordForm);
        mockMvc.perform(post("/mypage/edit/info/password")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(requestBody)
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        Account account = accountRepository.findByEmail(TEST_EMAIL);
        assertFalse(passwordEncoder.matches(passwordForm.getNewPassword1(), account.getPassword()));
    }

    @WithAccount(TEST_EMAIL)
    @Test
    @DisplayName("로그인 정보 변경 처리 - 새 비밀번호 값이 다름")
    void editPasswordsInfo_with_wrong_value_2() throws Exception {
        PasswordForm passwordForm = new PasswordForm();
        passwordForm.setCurrentPassword(testProperties.getPassword());
        passwordForm.setNewPassword1(testProperties.getPassword() + "new1");
        passwordForm.setNewPassword2(testProperties.getPassword() + "new2");

        String requestBody = objectMapper.writeValueAsString(passwordForm);
        mockMvc.perform(post("/mypage/edit/info/password")
                    .characterEncoding("utf8")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(requestBody)
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        Account account = accountRepository.findByEmail(TEST_EMAIL);
        assertFalse(passwordEncoder.matches(passwordForm.getNewPassword1(), account.getPassword()));
    }

    @WithAccount(TEST_EMAIL)
    @Test
    @DisplayName("웹 정보 수신 방법 변경 처리")
    void editWebReceptionInfo() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        boolean prev = account.isReceivingInfoByWeb();

        mockMvc.perform(post("/mypage/edit/info/web-reception")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertEquals(!prev, account.isReceivingInfoByWeb());
    }

    @WithAccount(TEST_EMAIL)
    @Test
    @DisplayName("이메일 정보 수신 방법 변경 처리")
    void editEmailReceptionInfo() throws Exception {
        Account account = accountRepository.findByEmail(TEST_EMAIL);
        boolean prev = account.isReceivingInfoByEmail();

        mockMvc.perform(post("/mypage/edit/info/email-reception")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername(TEST_EMAIL));

        assertEquals(!prev, account.isReceivingInfoByEmail());
    }

    @WithAccount(TEST_EMAIL)
    @Test
    @DisplayName("회원 탈퇴 처리")
    void signOut() throws Exception {
        mockMvc.perform(post("/sign-out")
                    .with(csrf()))
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/"))
                .andExpect(unauthenticated()); // 로그아웃됨

        assertTrue(accountRepository.findByEmail(TEST_EMAIL).isDeleted());
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("마일리지 조회 화면 보이는지 테스트")
    @Test
    public void mileageForm() throws Exception {
        mockMvc.perform(get("/mypage/mileage"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("account/mileage"))
                .andExpect(model().attributeExists("account"))
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

    @WithAccount(TEST_EMAIL)
    @DisplayName("멤버쉽 조회 화면 보이는지 테스트")
    @Test
    public void membershipForm() throws Exception {
        mockMvc.perform(get("/mypage/membership"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("account/membership"))
                .andExpect(model().attributeExists("account"))
                .andExpect(authenticated().withUsername(TEST_EMAIL));
    }

}
