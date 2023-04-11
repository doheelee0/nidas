package com.nidas.modules.account;

import com.nidas.modules.account.form.AdminAccountSearchForm;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;

@Transactional(readOnly = true)
public interface AccountRepositoryExtension {

    Page<Account> findByAdminAccountSearchForm(AdminAccountSearchForm adminAccountSearchForm, Pageable pageable);

}
