package com.nidas.modules.review;

import com.nidas.infra.exception.InvalidParameterException;
import com.nidas.modules.account.Account;
import com.nidas.modules.account.AccountService;
import com.nidas.modules.account.CurrentAccount;
import com.nidas.modules.order.OrderDetails;
import com.nidas.modules.order.OrderService;
import com.nidas.modules.review.form.AdminReviewInfo;
import com.nidas.modules.review.form.ReviewDetailsForm;
import com.nidas.modules.review.form.ReviewForm;
import com.nidas.modules.review.form.ReviewIdForm;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class ReviewRestController {

    private final OrderService orderService;
    private final AccountService accountService;
    private final ReviewService reviewService;
    private final ModelMapper modelMapper;
    private final ReviewRepository reviewRepository;

    @PostMapping("/order/details/{id}/review/write")
    public ResponseEntity writeReview(@PathVariable Long id, @CurrentAccount Account account,
                                      @Valid @RequestBody ReviewForm reviewForm, Errors errors) {
        if (errors.hasErrors()) {
            throw new InvalidParameterException(errors.getAllErrors().get(0).getDefaultMessage());
        }
        OrderDetails orderDetails = orderService.getOrderDetails(id, account);
        reviewService.write(orderDetails, account, reviewForm);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/review/{id}/update")
    public ResponseEntity updateReview(@PathVariable Long id, @CurrentAccount Account account,
                                       @Valid @RequestBody ReviewForm reviewForm, Errors errors) {
        if (errors.hasErrors()) {
            throw new InvalidParameterException(errors.getAllErrors().get(0).getDefaultMessage());
        }
        Review review = reviewService.getReview(id, account);
        reviewService.update(review, reviewForm);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/review/{id}/delete")
    public ResponseEntity deleteReview(@PathVariable Long id, @CurrentAccount Account account) {
        Review review = reviewService.getReview(id, account);
        reviewService.delete(review, account);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/product/{productId}/review/image")
    public ResponseEntity getImageReview(@PathVariable("productId") Long productId,
                                         @PageableDefault(size = 20, sort = "createdDateTime", direction = Sort.Direction.DESC) Pageable pageable) {
        Page<Review> reviewPage = reviewRepository.findReviewByProduct(productId, true, pageable);
        return ResponseEntity.ok().body(putReviewPageInfoToMap(reviewPage));
    }

    @GetMapping("/product/{productId}/review/content")
    public ResponseEntity getReviewContent(@PathVariable("productId") Long productId,
                                           @PageableDefault(size = 20, sort = "createdDateTime", direction = Sort.Direction.DESC) Pageable pageable) {
        Page<Review> reviewPage = reviewRepository.findReviewByProduct(productId, false, pageable);
        Map<String, Object> map = putReviewPageInfoToMap(reviewPage);

        int startPage = reviewPage.getNumber() / 10 * 10;
        int endPage = Math.min(startPage + 9, reviewPage.getTotalPages() - 1);
        map.put("startPage", startPage);
        map.put("endPage", endPage);
        return ResponseEntity.ok().body(map);
    }

    private Map<String, Object> putReviewPageInfoToMap(Page<Review> reviewPage) {
        List<ReviewDetailsForm> reviewList = reviewPage.getContent().stream().map(review -> {
            ReviewDetailsForm reviewDetailsForm = modelMapper.map(review, ReviewDetailsForm.class);
            reviewDetailsForm.setEmail(review.getAccount().getAnonymousEmail());
            reviewDetailsForm.setProductDetails(review.getOrderDetails().getProductDetails());
            return reviewDetailsForm;
        }).collect(Collectors.toList());

        Map<String, Object> map = new HashMap<>();
        map.put("currentPage", reviewPage.getNumber());
        map.put("hasPrevious", reviewPage.hasPrevious());
        map.put("hasNext", reviewPage.hasNext());
        map.put("reviewList", reviewList);
        map.put("totalCount", reviewPage.getTotalElements());
        return map;
    }

    @GetMapping("/admin/management/account/{id}/review")
    public ResponseEntity getAccountReviewList(@PathVariable("id") Account account) {
        List<AdminReviewInfo> reviewList = reviewRepository.findByAccount(account).stream().map(review -> {
            AdminReviewInfo adminReviewInfo = modelMapper.map(review, AdminReviewInfo.class);
            adminReviewInfo.setProduct(review.getProduct());
            return adminReviewInfo;
        }).collect(Collectors.toList());
        return ResponseEntity.ok().body(reviewList);
    }

    @PostMapping("/admin/review/delete")
    public ResponseEntity deleteAccountReview(@Valid @RequestBody ReviewIdForm reviewIdForm, Errors errors) {
        if (errors.hasErrors()) {
            throw new InvalidParameterException(errors.getAllErrors().get(0).getDefaultMessage());
        }
        Account account = accountService.getAccount(reviewIdForm.getAccountId());
        Review review = reviewService.getReview(reviewIdForm.getReviewId(), account);
        reviewService.delete(review, account);
        return ResponseEntity.ok().build();
    }

}
