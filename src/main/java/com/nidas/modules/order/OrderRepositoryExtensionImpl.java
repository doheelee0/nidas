package com.nidas.modules.order;

import com.nidas.modules.account.QAccount;
import com.nidas.modules.order.form.AdminOrderSearchForm;
import com.nidas.modules.product.QProduct;
import com.nidas.modules.product.QProductDetails;
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

public class OrderRepositoryExtensionImpl extends QuerydslRepositorySupport implements OrderRepositoryExtension {

    QOrder order = QOrder.order;
    QAccount account = QAccount.account;
    QOrderDetails orderDetails = QOrderDetails.orderDetails;
    QProductDetails productDetails = QProductDetails.productDetails;
    QProduct product = QProduct.product;

    public OrderRepositoryExtensionImpl() {
        super(Order.class);
    }

    @Override
    public Page<Order> findByAdminOrderSearchForm(AdminOrderSearchForm adminOrderSearchForm, Pageable pageable) {
        BooleanBuilder builder = new BooleanBuilder();

        builder.and(order.orderNumber.contains(adminOrderSearchForm.getOrderNumber()));

        builder.and(account.email.containsIgnoreCase(adminOrderSearchForm.getEmail()));

        builder.and(product.name.containsIgnoreCase(adminOrderSearchForm.getProductName()));

        List<OrderStatus> orderStatusList = Arrays.stream(adminOrderSearchForm.getOrderStatus().split(","))
                .filter(OrderStatus::contains)
                .map(o -> OrderStatus.valueOf(o.toUpperCase()))
                .collect(Collectors.toList());
        if (!orderStatusList.isEmpty()) {
            builder.and(orderDetails.status.in(orderStatusList));
        }

        JPQLQuery<Order> query = from(order)
                .where(builder)
                .leftJoin(order.account, QAccount.account).fetchJoin()
                .leftJoin(order.orderDetails, QOrderDetails.orderDetails).fetchJoin()
                .leftJoin(orderDetails.productDetails, QProductDetails.productDetails).fetchJoin()
                .leftJoin(productDetails.product, QProduct.product).fetchJoin()
                .orderBy(order.createdDateTime.desc())
                .distinct();
        JPQLQuery<Order> pageableQuery = getQuerydsl().applyPagination(pageable, query);
        QueryResults<Order> fetchResults = pageableQuery.fetchResults();
        return new PageImpl<>(fetchResults.getResults(), pageable, fetchResults.getTotal());
    }
}
