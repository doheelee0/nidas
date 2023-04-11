package com.nidas.modules.order;

import com.nidas.modules.order.form.AdminOrderSearchForm;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;

@Transactional(readOnly = true)
public interface OrderRepositoryExtension {

    Page<Order> findByAdminOrderSearchForm(AdminOrderSearchForm adminOrderSearchForm, Pageable pageable);

}
