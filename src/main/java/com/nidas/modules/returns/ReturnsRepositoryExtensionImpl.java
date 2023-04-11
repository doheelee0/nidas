package com.nidas.modules.returns;

import com.nidas.modules.account.QAccount;
import com.nidas.modules.order.OrderStatus;
import com.nidas.modules.order.QOrder;
import com.nidas.modules.order.QOrderDetails;
import com.nidas.modules.product.QProduct;
import com.nidas.modules.product.QProductDetails;
import com.nidas.modules.returns.form.AdminReturnsSearchForm;
import com.querydsl.core.BooleanBuilder;
import com.querydsl.core.QueryResults;
import com.querydsl.jpa.JPQLQuery;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.support.QuerydslRepositorySupport;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class ReturnsRepositoryExtensionImpl extends QuerydslRepositorySupport implements ReturnsRepositoryExtension {

    QReturns returns = QReturns.returns;
    QOrderDetails orderDetails = QOrderDetails.orderDetails;
    QProductDetails productDetails = QProductDetails.productDetails;
    QOrder order = QOrder.order;
    QAccount account = QAccount.account;
    QProduct product = QProduct.product;

    public ReturnsRepositoryExtensionImpl() {
        super(Returns.class);
    }

    @Override
    public Page<Returns> findByAdminReturnsSearchForm(AdminReturnsSearchForm adminReturnsSearchForm, Pageable pageable) {
        BooleanBuilder builder = new BooleanBuilder();

        builder.and(order.orderNumber.contains(adminReturnsSearchForm.getOrderNumber()));

        builder.and(account.email.containsIgnoreCase(adminReturnsSearchForm.getEmail()));

        builder.and(product.name.containsIgnoreCase(adminReturnsSearchForm.getProductName()));

        List<OrderStatus> returnsStatusList = Arrays.stream(adminReturnsSearchForm.getReturnsStatus().split(","))
                .filter(OrderStatus::contains)
                .map(o -> OrderStatus.valueOf(o.toUpperCase()))
                .collect(Collectors.toList());
        if (!returnsStatusList.isEmpty()) {
            builder.and(orderDetails.status.in(returnsStatusList));
        }

        JPQLQuery<Returns> query = from(returns)
                .where(builder)
                .leftJoin(returns.account, QAccount.account).fetchJoin()
                .leftJoin(returns.orderDetails, QOrderDetails.orderDetails).fetchJoin()
                .leftJoin(orderDetails.order, QOrder.order).fetchJoin()
                .leftJoin(orderDetails.productDetails, QProductDetails.productDetails).fetchJoin()
                .leftJoin(productDetails.product, QProduct.product).fetchJoin()
                .orderBy(returns.createdDateTime.desc());
        JPQLQuery<Returns> pageableQuery = getQuerydsl().applyPagination(pageable, query);
        QueryResults<Returns> fetchResults = pageableQuery.fetchResults();
        return new PageImpl<>(fetchResults.getResults(), pageable, fetchResults.getTotal());
    }
}
