package com.nidas.modules.faq;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

@Transactional(readOnly = true)
public interface FaqRepository extends JpaRepository<Faq, Long> {

    @Query("SELECT f FROM Faq f WHERE (:type IS NULL OR f.type = :type) AND " +
            "(LOWER(f.title) LIKE LOWER(CONCAT('%', :keyword, '%')) OR LOWER(f.content) LIKE LOWER(CONCAT('%', :keyword, '%')))")
    Page<Faq> findByTypeAndKeyword(@Param("type") FaqType type, @Param("keyword") String keyword, Pageable pageable);

}
