package com.nidas.modules.faq;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequiredArgsConstructor
public class FaqRestController {

    private final FaqService faqService;

    @PostMapping("/admin/faq/write")
    public ResponseEntity writeFaq(@RequestBody @Valid FaqForm faqForm) {
        faqService.write(faqForm);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/admin/faq/{id}/update")
    public ResponseEntity updateFaq(@PathVariable Long id, @RequestBody @Valid FaqForm faqForm) {
        Faq faq = faqService.getFaq(id);
        faqService.update(faq, faqForm);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/admin/faq/{id}/delete")
    public ResponseEntity deleteFaq(@PathVariable Long id) {
        Faq faq = faqService.getFaq(id);
        faqService.delete(faq);
        return ResponseEntity.ok().build();
    }

}
