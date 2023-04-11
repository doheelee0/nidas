package com.nidas.modules.product;

import com.nidas.modules.product.form.AdminProductSearchForm;
import com.nidas.modules.product.form.ProductSearchForm;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;

@Transactional(readOnly = true)
public interface ProductRepositoryExtension {

    Page<Product> findByAdminProductSearchForm(Pageable pageable, AdminProductSearchForm adminProductSearchForm);

    Page<Product> findByProductSearchForm(Pageable pageable, ProductSearchForm productSearchForm);

    Page<Product> findByKeywords(Pageable pageable, String keywords, boolean deleted);

}
