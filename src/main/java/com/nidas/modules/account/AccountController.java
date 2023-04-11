package com.nidas.modules.account;

import com.nidas.modules.account.form.AdminAccountSearchForm;
import com.nidas.modules.account.form.DetailsForm;
import com.nidas.modules.account.form.PasswordForm;
import com.nidas.modules.account.form.SignUpForm;
import com.nidas.modules.account.validator.SignUpFormValidator;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

@Controller
@RequiredArgsConstructor
public class AccountController {

    private final AccountService accountService;
    private final AccountRepository accountRepository;
    private final SignUpFormValidator signUpFormValidator;
    private final ModelMapper modelMapper;

    @InitBinder("signUpForm")
    public void validateSignUpForm(WebDataBinder webDataBinder) {
        webDataBinder.addValidators(signUpFormValidator);
    }

    @GetMapping("/sign-up")
    public String signUpForm(Model model) {
        model.addAttribute(new SignUpForm());
        return "account/sign-up";
    }

    @PostMapping("/sign-up")
    public String signUp(@Valid SignUpForm signUpForm, Errors errors) {
        if (errors.hasErrors()) {
            return "account/sign-up";
        }
        Account account = accountService.processNewAccount(signUpForm);
        accountService.login(account);
        return "redirect:/";
    }

    @GetMapping("/check-email-token")
    public String checkEmailToken(String email, String token, Model model) {
        Account account = accountRepository.findByEmail(email);
        if (account == null || account.isDeleted() || !account.isValidEmailCheckToken(token)) {
            model.addAttribute("errorMessage", "잘못된 이메일 인증 링크입니다.");
            return "account/checked-email";
        }
        accountService.completeSignUp(account);
        accountService.login(account);
        model.addAttribute("successMessage", account.getName() + "님의 이메일 인증이 성공적으로 처리되었습니다. ");
        return "account/checked-email";
    }

    @GetMapping("/login")
    public String login() {
        return "account/login";
    }

    @GetMapping("/find-password")
    public String findPasswordForm() {
        return "account/find-password";
    }

    @PostMapping("/find-password")
    public String findPassword(String email, Model model, RedirectAttributes attributes) {
        Account account = accountRepository.findByEmail(email);
        if (account == null || account.isDeleted() ) {
            model.addAttribute("errorMessage", "존재하지 않는 계정입니다.");
            return "account/find-password";
        }
        if (!account.canSendPasswordFindToken()) {
            model.addAttribute("errorMessage", account.getPasswordFindTokenCoolTime() + "분 후에 메일을 보낼 수 있습니다.");
            return "account/find-password";
        }
        accountService.processPasswordFind(account);
        attributes.addFlashAttribute("successMessage", "비밀번호 찾기 인증 코드를 보냈습니다. 해당 이메일로 로그인해서 링크를 클릭해주세요.");
        return "redirect:/find-password";
    }

    @GetMapping("/check-password-find-token")
    public String checkPasswordFindToken(String email, String token, Model model) {
        Account account = accountRepository.findByEmail(email);
        if (account == null || account.isDeleted() || !account.isValidPasswordFindToken(token)) {
            model.addAttribute("errorMessage", "잘못된 인증링크로 인해 비밀번호 찾기에 실패했습니다.");
            return "account/checked-email";
        }
        accountService.completePasswordFind(account);
        accountService.login(account);
        model.addAttribute("successMessage", account.getName() + "님의 인증이 성공적으로 처리되었습니다.\n 계정설정에서 새 비밀번호로 변경해주세요.");
        return "account/checked-email";
    }

    @GetMapping("/mypage/edit/info")
    public String editInfoForm(@CurrentAccount Account account, Model model) {
        model.addAttribute(account);
        model.addAttribute(modelMapper.map(account, DetailsForm.class));
        model.addAttribute(modelMapper.map(account, PasswordForm.class));
        return "account/edit-info";
    }

    @PostMapping("/sign-out")
    public String signOut(@CurrentAccount Account account, HttpServletRequest request, HttpServletResponse response) {
        accountService.delete(account, request, response);
        return "redirect:/";
    }

    @GetMapping("/mypage/mileage")
    public String mileageForm(@CurrentAccount Account account, Model model) {
        model.addAttribute(account);
        return "account/mileage";
    }

    @GetMapping("/mypage/membership")
    public String membershipForm(@CurrentAccount Account account, Model model) {
        model.addAttribute(account);
        return "account/membership";
    }

    @GetMapping("/admin/management/account")
    public String getAccountList(@PageableDefault(size = 20) Pageable pageable,
                                 AdminAccountSearchForm adminAccountSearchForm, Model model) {
        Page<Account> accountPage = accountRepository.findByAdminAccountSearchForm(adminAccountSearchForm, pageable);
        model.addAttribute("accountPage", accountPage);
        return "account/admin/account-management";
    }

    @GetMapping("/admin/management/account/{id}")
    public String getAccountDetails(@PathVariable Long id, Model model) {
        Account account = accountService.getAccount(id);
        model.addAttribute(account);
        return "account/admin/details";
    }

}
