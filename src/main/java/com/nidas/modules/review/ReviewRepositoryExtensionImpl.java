package com.nidas.modules.review;

import com.nidas.modules.account.QAccount;
import com.nidas.modules.order.QOrderDetails;
import com.nidas.modules.product.QProduct;
import com.nidas.modules.product.QProductDetails;
import com.nidas.modules.review.form.AdminReviewSearchForm;
import com.querydsl.core.QueryResults;
import com.querydsl.jpa.JPQLQuery;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.support.QuerydslRepositorySupport;

public class ReviewRepositoryExtensionImpl extends QuerydslRepositorySupport implements ReviewRepositoryExtension {

    QReview review = QReview.review;
    QOrderDetails orderDetails = QOrderDetails.orderDetails;

    public ReviewRepositoryExtensionImpl() {
        super(Review.class);
    }

    @Override
    public Page<Review> findReviewByProduct(Long productId, boolean imageReviewOnly, Pageable pageable) {
        JPQLQuery<Review> query = from(review)
                .where(review.product.id.eq(productId)
                        .and(imageReviewOnly ? review.image.isNotNull() : null)
                        .and(review.deleted.isFalse()))
                .leftJoin(review.account, QAccount.account).fetchJoin()
                .leftJoin(review.orderDetails, QOrderDetails.orderDetails).fetchJoin()
                .leftJoin(orderDetails.productDetails, QProductDetails.productDetails).fetchJoin();

        JPQLQuery<Review> pageableQuery = getQuerydsl().applyPagination(pageable, query);
        QueryResults<Review> fetchResults = pageableQuery.fetchResults();
        return new PageImpl<>(fetchResults.getResults(), pageable, fetchResults.getTotal());
    }

    @Override
    public Page<Review> findByAdminReviewSearchForm(AdminReviewSearchForm adminReviewSearchForm, Pageable pageable) {
        JPQLQuery<Review> query = from(review)
                .where(review.account.email.containsIgnoreCase(adminReviewSearchForm.getEmail())
                        .and(review.product.name.containsIgnoreCase(adminReviewSearchForm.getProductName()))
                        .and(adminReviewSearchForm.isExceptDeleted() ? review.deleted.isFalse() : null))
                .leftJoin(review.account, QAccount.account).fetchJoin()
                .leftJoin(review.product, QProduct.product).fetchJoin()
                .orderBy(review.createdDateTime.desc());

        JPQLQuery<Review> pageableQuery = getQuerydsl().applyPagination(pageable, query);
        QueryResults<Review> fetchResults = pageableQuery.fetchResults();
        return new PageImpl<>(fetchResults.getResults(), pageable, fetchResults.getTotal());
    }

}
