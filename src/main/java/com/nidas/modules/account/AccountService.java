package com.nidas.modules.account;

import com.nidas.infra.config.AppProperties;
import com.nidas.infra.exception.ResourceNotFoundException;
import com.nidas.infra.mail.EmailMessage;
import com.nidas.infra.mail.EmailService;
import com.nidas.modules.account.form.DetailsForm;
import com.nidas.modules.account.form.PasswordForm;
import com.nidas.modules.account.form.SignUpForm;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
@Transactional
@RequiredArgsConstructor
public class AccountService implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;
    private final ModelMapper modelMapper;
    private final AccountRepository accountRepository;
    private final AppProperties appProperties;
    private final TemplateEngine templateEngine;
    private final EmailService emailService;

    public Account processNewAccount(SignUpForm signUpForm) {
        Account newAccount = saveNewAccount(signUpForm);
        sendEmailCheckToken(newAccount);
        return newAccount;
    }

    private Account saveNewAccount(SignUpForm signUpForm) {
        Account account = modelMapper.map(signUpForm, Account.class);
        account.setPassword(passwordEncoder.encode(signUpForm.getPassword1()));
        account.generateEmailCheckToken();
        return accountRepository.save(account);
    }

    private void sendEmailCheckToken(Account account) {
        Context context = new Context();
        context.setVariable("name", account.getName());
        context.setVariable("link", "/check-email-token?token=" + account.getEmailCheckToken() + "&email=" + account.getEmail());
        context.setVariable("linkName", "이메일 인증하기");
        context.setVariable("message", "이메일 확인을 위해 인증링크를 클릭해주세요.");
        context.setVariable("host", appProperties.getHost());
        String message = templateEngine.process("mail/simple-link", context);

        EmailMessage emailMessage = EmailMessage.builder()
                .to(account.getEmail())
                .subject("Nidas - 이메일 인증")
                .message(message)
                .build();
        emailService.sendEmail(emailMessage);
    }

    public void resendEmailCheckToken(Account account) {
        account.generateEmailCheckToken();
        accountRepository.save(account);
        sendEmailCheckToken(account);
    }

    public void completeSignUp(Account account) {
        account.completeSignUp();
    }

    public void login(Account account) {
        account.setLatestLoginDateTime(LocalDateTime.now());
        accountRepository.save(account);

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                new UserPrincipal(account),
                account.getPassword(),
                List.of(new SimpleGrantedAuthority(account.getAuthority().toString()))
        );
        SecurityContextHolder.getContext().setAuthentication(token);
    }

    @Transactional(readOnly = true)
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Account account = accountRepository.findByEmail(email);
        if (account == null || account.isDeleted()) {
            throw new UsernameNotFoundException(email);
        }
        return new UserPrincipal(account);
    }

    public void processPasswordFind(Account account) {
        account.generatePasswordFindToken();
        sendPasswordFindToken(account);
    }

    private void sendPasswordFindToken(Account account) {
        Context context = new Context();
        context.setVariable("name", account.getName());
        context.setVariable("link", "/check-password-find-token?token=" + account.getPasswordFindToken() + "&email=" + account.getEmail());
        context.setVariable("linkName", "이메일 인증하기");
        context.setVariable("message", "비밀번호를 찾기위해 인증링크를 클릭해주세요.");
        context.setVariable("host", appProperties.getHost());
        String message = templateEngine.process("mail/simple-link", context);

        EmailMessage emailMessage = EmailMessage.builder()
                .to(account.getEmail())
                .subject("Nidas - 비밀번호 찾기")
                .message(message)
                .build();
        emailService.sendEmail(emailMessage);
    }

    public void completePasswordFind(Account account) {
        String password = UUID.randomUUID().toString().replace("-", "").substring(0, 20);
        account.setPassword(passwordEncoder.encode(password));
        account.setPasswordFindToken(null);
        sendTempPassword(account, password);
    }

    private void sendTempPassword(Account account, String password) {
        Context context = new Context();
        context.setVariable("name", account.getName());
        context.setVariable("link", "/mypage/edit/info");
        context.setVariable("linkName", "비밀번호 변경하기");
        context.setVariable("message", "새 비밀번호: " + password +
                "\n임시 비밀번호로 로그인할 수 있으나 가급적이면 새 비밀번호로 변경해주세요.");
        context.setVariable("host", appProperties.getHost());
        String message = templateEngine.process("mail/simple-link", context);

        EmailMessage emailMessage = EmailMessage.builder()
                .to(account.getEmail())
                .subject("Nidas - 임시 비밀번호 발급")
                .message(message)
                .build();
        emailService.sendEmail(emailMessage);
    }

    public void editDetailsInfo(Account account, DetailsForm detailsForm) {
        modelMapper.map(detailsForm, account);
        accountRepository.save(account);
    }

    public void editPasswordInfo(Account account, PasswordForm passwordForm) {
        account.setPassword(passwordEncoder.encode(passwordForm.getNewPassword1()));
        accountRepository.save(account);
    }

    public void toggleWebReceptionInfo(Account account) {
        account.setReceivingInfoByWeb(!account.isReceivingInfoByWeb());
        accountRepository.save(account);
    }

    public void toggleEmailReceptionInfo(Account account) {
        account.setReceivingInfoByEmail(!account.isReceivingInfoByEmail());
        accountRepository.save(account);
    }

    public void delete(Account account, HttpServletRequest request, HttpServletResponse response) {
        account.setDeleted(true);
        accountRepository.save(account);
        logout(request, response);
    }

    public void logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null){
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }
        SecurityContextHolder.getContext().setAuthentication(null);
    }

    public void updateMileage(Account account, Integer mileage) {
        account.setMileage(account.getMileage() + mileage);
    }

    public Account getAccount(Long id) {
        Account account = accountRepository.findById(id).orElseThrow(() -> {
            throw new ResourceNotFoundException("존재하지 않는 회원입니다.");
        });
        return account;
    }
}
