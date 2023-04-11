package com.nidas.modules.returns;

import com.nidas.infra.exception.InvalidParameterException;
import com.nidas.modules.account.Account;
import com.nidas.modules.account.AccountService;
import com.nidas.modules.account.CurrentAccount;
import com.nidas.modules.order.OrderDetails;
import com.nidas.modules.order.OrderService;
import com.nidas.modules.returns.form.ReturnsForm;
import com.nidas.modules.returns.form.ReturnsIdForm;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequiredArgsConstructor
public class ReturnsRestController {

    private final OrderService orderService;
    private final ReturnsService returnsService;
    private final AccountService accountService;

    @PostMapping("/order/details/{id}/exchange")
    public ResponseEntity applyForExchange(@PathVariable Long id, @CurrentAccount Account account,
                                           @Valid @RequestBody ReturnsForm returnsForm, Errors errors) {
        if (errors.hasErrors()) {
            throw new InvalidParameterException(errors.getAllErrors().get(0).getDefaultMessage());
        }
        if (!ReturnsType.getExchangeValues().contains(returnsForm.getType())) {
            throw new InvalidParameterException("잘못된 교환 사유입니다.");
        }
        OrderDetails orderDetails = orderService.getOrderDetailsToUpdateStatus(id, account);
        returnsService.applyForExchange(orderDetails, account, returnsForm);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/order/details/{id}/return")
    public ResponseEntity applyForReturn(@PathVariable Long id, @CurrentAccount Account account,
                                         @Valid @RequestBody ReturnsForm returnsForm, Errors errors) {
        if (errors.hasErrors()) {
            throw new InvalidParameterException(errors.getAllErrors().get(0).getDefaultMessage());
        }
        if (!ReturnsType.getReturnValues().contains(returnsForm.getType())) {
            throw new InvalidParameterException("잘못된 환불 사유입니다.");
        }
        OrderDetails orderDetails = orderService.getOrderDetailsToUpdateStatus(id, account);
        returnsService.applyForReturn(orderDetails, account, returnsForm);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/returns/{id}/delete")
    public ResponseEntity deleteReturns(@PathVariable Long id, @CurrentAccount Account account) {
        Returns returns = returnsService.getReturns(id, account);
        returnsService.delete(returns);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/admin/returns/complete")
    public ResponseEntity completeReturns(@Valid @RequestBody ReturnsIdForm returnsIdForm, Errors errors) {
        if (errors.hasErrors()) {
            throw new InvalidParameterException(errors.getAllErrors().get(0).getDefaultMessage());
        }
        Account account = accountService.getAccount(returnsIdForm.getAccountId());
        Returns returns = returnsService.getReturns(returnsIdForm.getReturnsId(), account);
        returnsService.complete(returns, account);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/admin/returns/delete")
    public ResponseEntity deleteAccountReturns(@Valid @RequestBody ReturnsIdForm returnsIdForm, Errors errors) {
        if (errors.hasErrors()) {
            throw new InvalidParameterException(errors.getAllErrors().get(0).getDefaultMessage());
        }
        Account account = accountService.getAccount(returnsIdForm.getAccountId());
        Returns returns = returnsService.getReturns(returnsIdForm.getReturnsId(), account);
        returnsService.delete(returns);
        return ResponseEntity.ok().build();
    }

}
