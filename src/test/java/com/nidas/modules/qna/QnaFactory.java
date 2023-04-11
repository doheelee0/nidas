package com.nidas.modules.qna;

import com.nidas.modules.account.Account;
import com.nidas.modules.product.Product;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Component
public class QnaFactory {

    @Autowired private QnaRepository qnaRepository;

    public Qna createQna(Account account, Product product) {
        Qna qna = new Qna();
        qna.setType(QnaType.PRODUCT_QNA);
        qna.setContent("test");
        qna.setCreatedDateTime(LocalDateTime.now());
        qna.setAccount(account);
        qna.setProduct(product);
        return qnaRepository.save(qna);
    }

    public Qna replyQna(Qna qna) {
        QnaReply qnaReply = new QnaReply();
        qnaReply.setContent("test");
        qnaReply.setCreatedDateTime(LocalDateTime.now());
        qna.setQnaReply(qnaReply);
        return qnaRepository.save(qna);
    }

    public List<Qna> createQnas(Account account, Product product, int iter) {
        List<Qna> qnaList = new ArrayList<>();
        for (int i = 0; i < iter; i++) {
            Qna qna = new Qna();
            qna.setType(QnaType.PRODUCT_QNA);
            qna.setContent("test" + i);
            qna.setCreatedDateTime(LocalDateTime.now().plusSeconds(i));
            qna.setAccount(account);
            qna.setProduct(product);
            qnaList.add(qna);
        }
        return qnaRepository.saveAll(qnaList);
    }

}
