package com.nidas.modules.favorites;

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
public class FavoritesInterceptor implements HandlerInterceptor {

    private final FavoritesRepository favoritesRepository;

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (modelAndView != null && !isRedirectView(modelAndView) && isMypageUrl(request) && authentication != null
                && authentication.getPrincipal() instanceof UserPrincipal) {
            Account account = ((UserPrincipal) authentication.getPrincipal()).getAccount();
            modelAndView.addObject("myFavoritesCount", favoritesRepository.countByAccount(account));
        }
    }

    private boolean isRedirectView(ModelAndView modelAndView) {
        return modelAndView.getViewName().startsWith("redirect:") || modelAndView.getView() instanceof RedirectView;
    }

    private boolean isMypageUrl(HttpServletRequest request) {
        return request.getRequestURI().startsWith("/mypage");
    }

}
