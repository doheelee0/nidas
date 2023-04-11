package com.nidas.modules.faq;

import com.nidas.infra.exception.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class FaqService {

    private final FaqRepository faqRepository;
    private final ModelMapper modelMapper;

    public void write(FaqForm faqForm) {
        Faq newFaq = modelMapper.map(faqForm, Faq.class);
        faqRepository.save(newFaq);
    }

    public Faq getFaq(Long id) {
        Faq faq = faqRepository.findById(id).orElseThrow(() -> {
            throw new ResourceNotFoundException("존재하지 않는 FAQ입니다.");
        });
        return faq;
    }

    public void update(Faq faq, FaqForm faqForm) {
        modelMapper.map(faqForm, faq);
    }

    public void delete(Faq faq) {
        faqRepository.delete(faq);
    }

}
