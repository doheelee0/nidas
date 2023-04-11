package com.nidas.modules.product;

import com.nidas.infra.exception.ResourceNotFoundException;
import com.nidas.modules.product.form.ProductForm;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@Transactional
@RequiredArgsConstructor
public class ProductService {

    private final ProductRepository productRepository;
    private final ModelMapper modelMapper;

    public Product create(ProductForm productForm) {
        Product product = modelMapper.map(productForm, Product.class);
        product.setThumbnail(productForm.getThumbnail());
        return productRepository.save(product);
    }

    public void update(Product product, ProductForm productForm) {
        product.removeAllImages();
        product.removeAllDetails();
        modelMapper.map(productForm, product);
        product.setThumbnail(productForm.getThumbnail());
        product.setUpdatedDateTime(LocalDateTime.now());
    }

    public Product getProduct(Long id) {
        Product product = productRepository.findProductWithImagesAndDetailsByIdAndDeletedFalse(id);
        checkIfExistingProduct(id, product);
        return product;
    }

    public Product getProductToUpdateStatus(Long id) {
        Product product = productRepository.findByIdAndDeletedFalse(id);
        checkIfExistingProduct(id, product);
        return product;
    }

    public Product getProductToUpdateDeleted(Long id, boolean deleted) {
        Product product = productRepository.findByIdAndDeleted(id, deleted);
        checkIfExistingProduct(id, product);
        return product;
    }

    private void checkIfExistingProduct(Long id, Product product) {
        if (product == null) {
            throw new ResourceNotFoundException(id + "에 해당하는 상품이 없습니다.");
        }
    }

    public void delete(Product product) {
        product.setDeleted(true);
    }

    public void restore(Product product) {
        product.setDeleted(false);
    }

    public void updateFavoritesCount(Product product, boolean added) {
        if (added) {
            product.setFavoritesCount(product.getFavoritesCount() + 1);
        } else {
            product.setFavoritesCount(product.getFavoritesCount() - 1);
        }
    }

    public void updateOrderInfo(ProductDetails[] productDetailsArray, Integer[] priceArray, Integer[] quantityArray) {
        for (int i = 0; i < productDetailsArray.length; i++) {
            ProductDetails productDetails = productDetailsArray[i];
            Integer price = priceArray[i];
            Integer quantity = quantityArray[i];
            productDetails.subtractStock(quantity);
            productDetails.getProduct().setSales(price, quantity);
        }
    }

    public void updateReviewInfo(Product product, Integer rank, int count) {
        int reviewCount = product.getReviewCount();
        int updatedReviewCount = reviewCount + count;

        product.setReviewCount(updatedReviewCount);
        if (updatedReviewCount > 0) {
            product.setRank((product.getRank() * reviewCount + rank) / (updatedReviewCount));
        } else {
            product.setRank(0.0);
        }
    }
}
