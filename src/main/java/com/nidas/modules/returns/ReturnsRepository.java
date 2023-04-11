package com.nidas.modules.returns;

import com.nidas.modules.account.Account;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Transactional(readOnly = true)
public interface ReturnsRepository extends JpaRepository<Returns, Long>, ReturnsRepositoryExtension {

    @EntityGraph("Returns.withOrderDetailsAndOrder")
    Returns findByIdAndAccount(Long id, Account account);

    @EntityGraph("Returns.withOrderDetailsAndOrderAndProductDetailsAndProduct")
    List<Returns> findByAccount(Account account);

}
