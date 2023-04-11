package com.nidas.modules.review;

import com.nidas.modules.account.Account;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Transactional(readOnly = true)
public interface ReviewRepository extends JpaRepository<Review, Long>, ReviewRepositoryExtension {

    @EntityGraph("Review.withAll")
    Review findByIdAndAccountAndDeletedFalse(Long id, Account account);

    @EntityGraph("Review.withProductAndOrderDetailsAndProductDetailsAndOrder")
    List<Review> findByAccountAndDeletedFalse(Account account);

    @EntityGraph("Review.withProduct")
    List<Review> findByAccount(Account account);

}
