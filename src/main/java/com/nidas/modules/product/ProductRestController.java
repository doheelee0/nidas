package com.nidas.modules.product;

import com.nidas.modules.product.form.ProductForm;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequiredArgsConstructor
public class ProductRestController {

    private final ProductService productService;

    @PostMapping("/admin/management/product/create")
    public ResponseEntity createProduct(@RequestBody @Valid ProductForm productForm) {
        productService.create(productForm);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/admin/management/product/{id}/update")
    public ResponseEntity updateProduct(@PathVariable Long id, @RequestBody @Valid ProductForm productForm) {
        Product product = productService.getProduct(id);
        productService.update(product, productForm);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/admin/management/product/{id}/delete")
    public ResponseEntity deleteProduct(@PathVariable Long id) {
        Product product = productService.getProductToUpdateDeleted(id, false);
        productService.delete(product);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/admin/management/product/{id}/restore")
    public ResponseEntity restoreProduct(@PathVariable Long id) {
        Product product = productService.getProductToUpdateDeleted(id, true);
        productService.restore(product);
        return ResponseEntity.ok().build();
    }

}
