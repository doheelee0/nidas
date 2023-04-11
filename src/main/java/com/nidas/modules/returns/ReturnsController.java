package com.nidas.modules.returns;

import com.nidas.modules.account.Account;
import com.nidas.modules.account.CurrentAccount;
import com.nidas.modules.order.OrderDetails;
import com.nidas.modules.order.OrderDetailsRepository;
import com.nidas.modules.order.OrderStatus;
import com.nidas.modules.returns.form.AdminReturnsSearchForm;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.ArrayList;
import java.util.List;

@Controller
@RequiredArgsConstructor
public class ReturnsController {

    private final OrderDetailsRepository orderDetailsRepository;
    private final ReturnsRepository returnsRepository;

    @GetMapping("/mypage/cancel-returns-list")
    public String getCancelReturnsList(@CurrentAccount Account account, Model model) {
        List<OrderDetails> cancelList = orderDetailsRepository.findByOrder_AccountAndStatusInOrderByOrder_CreatedDateTimeDesc(account, List.of(OrderStatus.CANCELED));
        List<Returns> returnsList = returnsRepository.findByAccount(account);
        putCategorizedReturnsList(returnsList, model);
        model.addAttribute("cancelList", cancelList);
        model.addAttribute(account);
        return "returns/cancel-returns-list";
    }

    private void putCategorizedReturnsList(List<Returns> returnsList, Model model) {
        List<Returns> returningList = new ArrayList<>();
        List<Returns> returnedList = new ArrayList<>();

        for (Returns returns : returnsList) {
            if (returns.getCompletedDateTime() == null) returningList.add(returns);
            else returnedList.add(returns);
        }
        model.addAttribute("returningList", returningList);
        model.addAttribute("returnedList", returnedList);
    }

    @GetMapping("/admin/management/returns")
    public String getAdminReturnsList(@PageableDefault(size = 20) Pageable pageable,
                                      AdminReturnsSearchForm adminReturnsSearchForm, Model model) {
        Page<Returns> returnsPage = returnsRepository.findByAdminReturnsSearchForm(adminReturnsSearchForm, pageable);
        model.addAttribute("returnsPage", returnsPage);
        return "returns/admin/returns-management";
    }

}
