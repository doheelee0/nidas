package com.nidas.modules.notice;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
@RequiredArgsConstructor
public class NoticeInterceptor implements HandlerInterceptor {

    private final NoticeRepository noticeRepository;

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
        if (modelAndView != null && !isRedirectView(modelAndView) && !isAdminView(modelAndView)) {
            modelAndView.addObject("newestNoticeList", noticeRepository.findTop5ByOrderByCreatedDateTimeDesc());
        }
    }

    private boolean isAdminView(ModelAndView modelAndView) {
        return modelAndView.getViewName().contains("/admin/");
    }

    private boolean isRedirectView(ModelAndView modelAndView) {
        return modelAndView.getViewName().startsWith("redirect:") || modelAndView.getView() instanceof RedirectView;
    }

}
