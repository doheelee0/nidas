package com.nidas.modules.returns;

import com.nidas.modules.returns.form.AdminReturnsSearchForm;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;

@Transactional(readOnly = true)
public interface ReturnsRepositoryExtension {

    Page<Returns> findByAdminReturnsSearchForm(AdminReturnsSearchForm adminReturnsSearchForm, Pageable pageable);

}
