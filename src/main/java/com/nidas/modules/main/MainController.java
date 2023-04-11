package com.nidas.modules.main;

import com.nidas.modules.product.ProductRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.time.LocalDateTime;

@Controller
@RequiredArgsConstructor
public class MainController {

    private final ProductRepository productRepository;

    @GetMapping("/")
    public String home(Model model) {
        model.addAttribute("productBest", productRepository.findTop10ByOrderByEntireSalesQuantityDesc());
        model.addAttribute("productNew", productRepository.findTop10ByOrderByCreatedDateTimeDesc());
        model.addAttribute("productHot", productRepository.findTop10ByCreatedDateTimeAfterOrderByEntireSalesQuantityDesc(LocalDateTime.now().minusMonths(3)));
        return "index";
    }

}
