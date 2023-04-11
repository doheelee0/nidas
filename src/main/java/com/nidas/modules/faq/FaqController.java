package com.nidas.modules.faq;

import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
public class FaqController {

    private final FaqService faqService;
    private final FaqRepository faqRepository;
    private final ModelMapper modelMapper;

    @GetMapping("/faq-list")
    public String getFaqList(@PageableDefault(size = 20) Pageable pageable,
                             @RequestParam(defaultValue = "") FaqType type,
                             @RequestParam(defaultValue = "") String keyword,
                             Model model) {
        Page<Faq> faqPage = faqRepository.findByTypeAndKeyword(type, keyword, pageable);
        model.addAttribute("type", type);
        model.addAttribute("keyword", keyword);
        model.addAttribute("faqPage", faqPage);
        return "faq/faq-list";
    }

    @GetMapping("/admin/management/faq")
    public String getAdminFaqList(@PageableDefault(size = 20) Pageable pageable,
                                  @RequestParam(defaultValue = "") FaqType type,
                                  @RequestParam(defaultValue = "") String keyword,
                                  Model model) {
        Page<Faq> faqPage = faqRepository.findByTypeAndKeyword(type, keyword, pageable);
        model.addAttribute("type", type);
        model.addAttribute("keyword", keyword);
        model.addAttribute("faqPage", faqPage);
        return "faq/admin/faq-management";
    }

    @GetMapping("/admin/faq/write")
    public String writeFaqForm(Model model) {
        model.addAttribute(new FaqForm());
        return "faq/admin/write-faq";
    }

    @GetMapping("/admin/faq/{id}/update")
    public String updateFaqForm(@PathVariable Long id, Model model) {
        Faq faq = faqService.getFaq(id);
        model.addAttribute("id", id);
        model.addAttribute(modelMapper.map(faq, FaqForm.class));
        return "faq/admin/update-faq";
    }

}
