package com.nidas.infra.config;

import com.nidas.modules.favorites.FavoritesInterceptor;
import com.nidas.modules.notice.NoticeInterceptor;
import com.nidas.modules.notification.NotificationInterceptor;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.StaticResourceLocation;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
@RequiredArgsConstructor
public class WebConfig implements WebMvcConfigurer {

    private final FavoritesInterceptor favoritesInterceptor;
    private final NotificationInterceptor notificationInterceptor;
    private final NoticeInterceptor noticeInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        List<String> staticResourcesPath = Arrays.stream(StaticResourceLocation.values())
                .flatMap(StaticResourceLocation::getPatterns)
                .collect(Collectors.toList());
        staticResourcesPath.add("/node_modules/**");

        registry.addInterceptor(favoritesInterceptor)
                .excludePathPatterns(staticResourcesPath); // 인터셉터를 제외할 url pattern

        registry.addInterceptor(notificationInterceptor)
                .excludePathPatterns(staticResourcesPath);

        registry.addInterceptor(noticeInterceptor)
                .excludePathPatterns(staticResourcesPath);
    }
}
