package com.nidas.modules.review;

import com.nidas.modules.account.Account;
import com.nidas.modules.account.CurrentAccount;
import com.nidas.modules.order.OrderDetails;
import com.nidas.modules.order.OrderDetailsRepository;
import com.nidas.modules.review.form.AdminReviewSearchForm;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;
import java.util.stream.Collectors;

@Controller
@RequiredArgsConstructor
public class ReviewController {

    private final OrderDetailsRepository orderDetailsRepository;
    private final ReviewRepository reviewRepository;

    @GetMapping("/mypage/writable-review-list")
    public String getWritableReviewList(@CurrentAccount Account account, Model model) {
        List<OrderDetails> orderDetailsList = orderDetailsRepository.findByOrder_Account(account)
                .stream().filter(OrderDetails::canReview).collect(Collectors.toList());
        model.addAttribute("orderDetailsList", orderDetailsList);
        model.addAttribute(account);
        return "review/writable-review-list";
    }

    @GetMapping("/mypage/review-list")
    public String getReviewList(@CurrentAccount Account account, Model model) {
        List<Review> reviewList = reviewRepository.findByAccountAndDeletedFalse(account);
        model.addAttribute("reviewList", reviewList);
        model.addAttribute(account);
        return "review/review-list";
    }

    @GetMapping("/admin/management/review")
    public String getAdminReviewList(@PageableDefault(size = 20) Pageable pageable,
                                     AdminReviewSearchForm adminReviewSearchForm, Model model) {
        Page<Review> reviewPage = reviewRepository.findByAdminReviewSearchForm(adminReviewSearchForm, pageable);
        model.addAttribute("reviewPage", reviewPage);
        return "review/admin/review-management";
    }

}
