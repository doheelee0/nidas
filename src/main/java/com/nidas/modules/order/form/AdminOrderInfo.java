package com.nidas.modules.order.form;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.nidas.modules.order.OrderDetails;
import com.nidas.modules.product.Product;
import com.nidas.modules.product.ProductDetails;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Getter @Setter
public class AdminOrderInfo {

    private String orderNumber;

    private String receiver;

    private String address1;

    private String address2;

    private String address3;

    private Long totalPrice;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy.MM.dd")
    private LocalDateTime createdDateTime;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy.MM.dd")
    private LocalDateTime arrivalDateTime;

    private List<AdminOrderDetailsInfo> orderDetailsList = new ArrayList<>();

    public void setOrderDetailsList(List<OrderDetails> orderDetailsList) {
        for (OrderDetails orderDetails : orderDetailsList) {
            ProductDetails productDetails = orderDetails.getProductDetails();
            Product product = productDetails.getProduct();

            AdminOrderDetailsInfo od = new AdminOrderDetailsInfo();
            od.setThumbnail(product.getThumbnail());
            od.setName(product.getName());
            od.setColor(productDetails.getColor().name());
            od.setSize(productDetails.getSize().getValue());
            od.setQuantity(orderDetails.getQuantity());
            od.setStatus(orderDetails.getStatus().getName());
            od.setReviewed(orderDetails.isReviewed());
            this.orderDetailsList.add(od);
        }
    }
}
