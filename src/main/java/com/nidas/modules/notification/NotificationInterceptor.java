package com.nidas.modules.notification;

import com.nidas.modules.account.Account;
import com.nidas.modules.account.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
@RequiredArgsConstructor
public class NotificationInterceptor implements HandlerInterceptor {

    private final NotificationRepository notificationRepository;

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (modelAndView != null && !isRedirectView(modelAndView) && !isAdminView(modelAndView) && authentication != null
                && authentication.getPrincipal() instanceof UserPrincipal) {
            Account account = ((UserPrincipal) authentication.getPrincipal()).getAccount();
            long notificationCountOfNotChecked = notificationRepository.countByAccountAndChecked(account, false);
            modelAndView.addObject("hasNotification", notificationCountOfNotChecked > 0);
            modelAndView.addObject("notificationCountOfNotChecked", notificationCountOfNotChecked);
        }
    }

    private boolean isAdminView(ModelAndView modelAndView) {
        return modelAndView.getViewName().contains("/admin/");
    }

    private boolean isRedirectView(ModelAndView modelAndView) {
        return modelAndView.getViewName().startsWith("redirect:") || modelAndView.getView() instanceof RedirectView;
    }

}
