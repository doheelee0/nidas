package com.nidas.modules.product;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Transactional(readOnly = true)
public interface ProductRepository extends JpaRepository<Product, Long>, ProductRepositoryExtension {

    @EntityGraph("Product.withImagesAndDetails")
    Product findProductWithImagesAndDetailsByIdAndDeletedFalse(Long id);

    Product findByIdAndDeleted(Long id, boolean deleted);

    Product findByIdAndDeletedFalse(Long id);

    List<Product> findTop10ByOrderByEntireSalesQuantityDesc();

    List<Product> findTop10ByOrderByCreatedDateTimeDesc();

    List<Product> findTop10ByCreatedDateTimeAfterOrderByEntireSalesQuantityDesc(LocalDateTime localDateTime);

}
