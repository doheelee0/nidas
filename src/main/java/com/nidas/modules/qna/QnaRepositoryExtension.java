package com.nidas.modules.qna;

import com.nidas.modules.qna.form.AdminQnaSearchForm;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;

@Transactional(readOnly = true)
public interface QnaRepositoryExtension {

    Page<Qna> findByAdminQnaSearchForm(AdminQnaSearchForm adminQnaSearchForm, Pageable pageable);

}
