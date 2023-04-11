package com.nidas.modules.qna;

import com.nidas.infra.exception.InvalidParameterException;
import com.nidas.infra.exception.ResourceNotFoundException;
import com.nidas.modules.account.Account;
import com.nidas.modules.product.Product;
import com.nidas.modules.qna.event.QnaReplyEvent;
import com.nidas.modules.qna.form.QnaWriteForm;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@Transactional
@RequiredArgsConstructor
public class QnaService {

    private final ModelMapper modelMapper;
    private final QnaRepository qnaRepository;
    private final ApplicationEventPublisher eventPublisher;

    public Qna writeQna(Product product, Account account, QnaWriteForm qnaWriteForm) {
        Qna newQna = modelMapper.map(qnaWriteForm, Qna.class);
        newQna.setCreatedDateTime(LocalDateTime.now());
        newQna.setProduct(product);
        newQna.setAccount(account);
        return qnaRepository.save(newQna);
    }

    public Qna getQna(Long id, Account account) {
        Qna qna = qnaRepository.findByIdAndAccount(id, account);
        if (qna == null) {
            throw new ResourceNotFoundException("존재하지 않는 Q&A입니다.");
        }
        return qna;
    }

    public void delete(Qna qna) {
        qnaRepository.delete(qna);
    }

    public void replyQna(Qna qna, String content) {
        if (qna.getQnaReply() != null) {
            throw new InvalidParameterException("이미 Q&A답변이 존재합니다.");
        }
        QnaReply qnaReply = new QnaReply();
        qnaReply.setContent(content);
        qnaReply.setCreatedDateTime(LocalDateTime.now());
        qna.setQnaReply(qnaReply);
        qnaRepository.save(qna);
        eventPublisher.publishEvent(new QnaReplyEvent(qna, "문의하신 Q&A에 답변이 달렸습니다."));
    }

    public void updateReply(Qna qna, String content) {
        checkIfExistingReply(qna);
        qna.getQnaReply().setContent(content);
        eventPublisher.publishEvent(new QnaReplyEvent(qna, "문의하신 Q&A에 답변이 수정되었습니다."));
    }

    public void deleteReply(Qna qna) {
        checkIfExistingReply(qna);
        qna.setQnaReply(null);
    }

    private void checkIfExistingReply(Qna qna) {
        if (qna.getQnaReply() == null) {
            throw new ResourceNotFoundException("Q&A답변이 존재하지 않습니다.");
        }
    }
}
