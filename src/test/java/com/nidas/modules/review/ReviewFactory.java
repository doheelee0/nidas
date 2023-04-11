package com.nidas.modules.review;

import com.nidas.modules.account.Account;
import com.nidas.modules.order.OrderDetails;
import com.nidas.modules.product.Product;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
public class ReviewFactory {

    @Autowired private ReviewRepository reviewRepository;

    public Review createReview(Account account, Product product, OrderDetails orderDetails) {
        Review review = new Review();
        review.setRank(5);
        review.setContent("review test1");
        review.setImage(product.getThumbnail());
        review.setCalculatedEarnedMileage(orderDetails.getUnitPrice(), orderDetails.getQuantity());
        review.setCreatedDateTime(LocalDateTime.now());
        review.setAccount(account);
        review.setProduct(product);
        review.setOrderDetails(orderDetails);
        return reviewRepository.save(review);
    }

}
