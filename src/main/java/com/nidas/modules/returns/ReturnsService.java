package com.nidas.modules.returns;

import com.nidas.infra.exception.InvalidParameterException;
import com.nidas.infra.exception.ResourceNotFoundException;
import com.nidas.modules.account.Account;
import com.nidas.modules.accountevent.AccountEventService;
import com.nidas.modules.order.OrderDetails;
import com.nidas.modules.order.OrderService;
import com.nidas.modules.order.OrderStatus;
import com.nidas.modules.returns.form.ReturnsForm;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@Transactional
@RequiredArgsConstructor
public class ReturnsService {

    private final OrderService orderService;
    private final AccountEventService accountEventService;
    private final ReturnsRepository returnsRepository;
    private final ModelMapper modelMapper;

    public void applyForExchange(OrderDetails orderDetails, Account account, ReturnsForm returnsForm) {
        if (!orderDetails.canReturns()) {
            throw new InvalidParameterException("현재 교환을 할 수 있는 상태가 아닙니다.");
        }
        createNewReturns(orderDetails, account, returnsForm);
        orderService.updateStatus(orderDetails, OrderStatus.EXCHANGING, true);
    }

    public void applyForReturn(OrderDetails orderDetails, Account account, ReturnsForm returnsForm) {
        if (!orderDetails.canReturns()) {
            throw new InvalidParameterException("현재 환불을 할 수 있는 상태가 아닙니다.");
        }
        createNewReturns(orderDetails, account, returnsForm);
        orderService.updateStatus(orderDetails, OrderStatus.RETURNING, true);
    }

    private Returns createNewReturns(OrderDetails orderDetails, Account account, ReturnsForm returnsForm) {
        Returns returns = modelMapper.map(returnsForm, Returns.class);
        returns.setCreatedDateTime(LocalDateTime.now());
        returns.setAccount(account);
        returns.setOrderDetails(orderDetails);
        return returnsRepository.save(returns);
    }

    public Returns getReturns(Long id, Account account) {
        Returns returns = returnsRepository.findByIdAndAccount(id, account);
        if (returns == null) {
            throw new ResourceNotFoundException("해당하는 반품신청이 존재하지 않습니다.");
        }
        return returns;
    }

    public void delete(Returns returns) {
        if (!returns.isNotCompleted()) {
            throw new InvalidParameterException("해당하는 반품신청을 취소할 수 없는 상태입니다.");
        }
        orderService.updateStatus(returns.getOrderDetails(), OrderStatus.DELIVERED, false);
        returnsRepository.delete(returns);
    }

    public void complete(Returns returns, Account account) {
        if (!returns.isNotCompleted()) {
            throw new InvalidParameterException("해당하는 반품신청을 완료할 수 없는 상태입니다.");
        }
        OrderDetails orderDetails = returns.getOrderDetails();
        if (orderDetails.getStatus() == OrderStatus.RETURNING) {
            orderService.updateStatus(orderDetails, OrderStatus.RETURNED, true);
            long orderDetailsTotalPrice = (long) orderDetails.getUnitPrice() * orderDetails.getQuantity();
            long orderDetailsMileage = (long) (orderDetails.getOrder().getMileageUsage() * ((double) orderDetailsTotalPrice / orderDetails.getOrder().getTotalPrice()));
            accountEventService.updateOrderInfo(account, -orderDetailsTotalPrice, -orderDetailsMileage, -1);
        } else { // OrderStatus.EXCHANGING
            orderService.updateStatus(orderDetails, OrderStatus.EXCHANGED, true);
        }
        returns.setCompletedDateTime(LocalDateTime.now());
    }
}
