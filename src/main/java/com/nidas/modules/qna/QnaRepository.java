package com.nidas.modules.qna;

import com.nidas.modules.account.Account;
import com.nidas.modules.product.Product;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Transactional(readOnly = true)
public interface QnaRepository extends JpaRepository<Qna, Long>, QnaRepositoryExtension {

    @EntityGraph("Qna.withQnaReplyAndAccount")
    Page<Qna> findByProduct(Product product, Pageable pageable);

    @EntityGraph("Qna.withQnaReplyAndProduct")
    List<Qna> findByAccount(Account account);

    @EntityGraph("Qna.withQnaReplyAndAccount")
    Qna findByIdAndAccount(Long id, Account account);

}
