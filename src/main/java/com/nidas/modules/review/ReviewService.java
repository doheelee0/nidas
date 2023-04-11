package com.nidas.modules.review;

import com.nidas.infra.exception.InvalidParameterException;
import com.nidas.infra.exception.ResourceNotFoundException;
import com.nidas.modules.account.Account;
import com.nidas.modules.account.AccountService;
import com.nidas.modules.order.OrderDetails;
import com.nidas.modules.order.OrderService;
import com.nidas.modules.product.Product;
import com.nidas.modules.product.ProductService;
import com.nidas.modules.review.form.ReviewForm;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@Transactional
@RequiredArgsConstructor
public class ReviewService {

    private final ReviewRepository reviewRepository;
    private final AccountService accountService;
    private final ProductService productService;
    private final OrderService orderService;
    private final ModelMapper modelMapper;

    public void write(OrderDetails orderDetails, Account account, ReviewForm reviewForm) {
        if (!orderDetails.canReview()) {
            throw new InvalidParameterException("해당 주문에 대해 리뷰를 작성할 수 없습니다.");
        }
        Product product = orderDetails.getProductDetails().getProduct();
        Review newReview = createNewReview(orderDetails, product, account, reviewForm);
        accountService.updateMileage(account, newReview.getEarnedMileage());
        productService.updateReviewInfo(product, newReview.getRank(), 1);
        orderService.markAsWrittenReview(orderDetails);
    }

    private Review createNewReview(OrderDetails orderDetails, Product product, Account account, ReviewForm reviewForm) {
        Review newReview = modelMapper.map(reviewForm, Review.class);
        newReview.setCalculatedEarnedMileage(orderDetails.getUnitPrice(), orderDetails.getQuantity());
        newReview.setCreatedDateTime(LocalDateTime.now());
        newReview.setAccount(account);
        newReview.setProduct(product);
        newReview.setOrderDetails(orderDetails);
        return reviewRepository.save(newReview);
    }

    public Review getReview(Long id, Account account) {
        Review review = reviewRepository.findByIdAndAccountAndDeletedFalse(id, account);
        if (review == null) {
            throw new ResourceNotFoundException("해당하는 리뷰가 존재하지 않습니다.");
        }
        return review;
    }

    public void update(Review review, ReviewForm reviewForm) {
        if (review.isEditable()) {
            int rankDiff = reviewForm.getRank() - review.getRank();
            modelMapper.map(reviewForm, review);
            review.setUpdatedDateTime(LocalDateTime.now());
            productService.updateReviewInfo(review.getProduct(), rankDiff, 0);
        } else {
            throw new InvalidParameterException("리뷰를 수정할 수 없습니다.");
        }
    }

    public void delete(Review review, Account account) {
        review.setDeleted(true);
        accountService.updateMileage(account, -review.getEarnedMileage());
        productService.updateReviewInfo(review.getProduct(), -review.getRank(), -1);
    }
}
