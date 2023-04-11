package com.nidas.modules.review;

import com.nidas.modules.review.form.AdminReviewSearchForm;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;

@Transactional(readOnly = true)
public interface ReviewRepositoryExtension {

    Page<Review> findReviewByProduct(Long productId, boolean imageReviewOnly, Pageable pageable);

    Page<Review> findByAdminReviewSearchForm(AdminReviewSearchForm adminReviewSearchForm, Pageable pageable);

}
