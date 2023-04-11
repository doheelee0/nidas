package com.nidas.modules.product;

import com.nidas.infra.config.AppProperties;
import com.nidas.modules.account.Account;
import com.nidas.modules.account.CurrentAccount;
import com.nidas.modules.product.form.AdminProductSearchForm;
import com.nidas.modules.product.form.ProductForm;
import com.nidas.modules.product.form.ProductSearchForm;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.stream.Collectors;
import java.util.stream.Stream;

@Controller
@RequiredArgsConstructor
public class ProductController {

    private final ProductRepository productRepository;
    private final ProductService productService;
    private final ModelMapper modelMapper;
    private final AppProperties appProperties;

    @GetMapping("/admin/management/product")
    public String getProductList(@PageableDefault(size = 20) Pageable pageable,
                                 AdminProductSearchForm adminProductSearchForm, Model model) {
        Page<Product> productPage = productRepository.findByAdminProductSearchForm(pageable, adminProductSearchForm);
        model.addAttribute("productPage", productPage);
        return "product/admin/product-management";
    }

    @GetMapping("/admin/management/product/create")
    public String createProductForm(Model model) {
        model.addAttribute("colorList", Stream.of(Color.values()).collect(Collectors.toList()));
        model.addAttribute(new ProductForm());
        return "product/admin/create-product";
    }

    @GetMapping("/admin/management/product/{id}/update")
    public String updateProductForm(@PathVariable Long id, Model model) {
        Product product = productService.getProduct(id);
        model.addAttribute("id", id);
        model.addAttribute(modelMapper.map(product, ProductForm.class));
        model.addAttribute("colorList", Stream.of(Color.values()).collect(Collectors.toList()));
        return "product/admin/update-product";
    }

    @GetMapping("/admin/management/product/restore")
    public String restoreProductForm(@PageableDefault(size = 20) Pageable pageable,
                                     @RequestParam(defaultValue = "") String keywords, Model model) {
        Page<Product> productPage = productRepository.findByKeywords(pageable, keywords, true);
        model.addAttribute("productPage", productPage);
        model.addAttribute("keywords", keywords);
        return "product/admin/restore-product";
    }

    @GetMapping("/products")
    public String searchProducts(@PageableDefault(size = 20) Pageable pageable, @CurrentAccount Account account,
                                 ProductSearchForm productSearchForm, Errors errors, Model model) {
        if (errors.hasErrors()) {
            model.addAttribute("productPage", Page.empty());
            return "product/product-list";
        }
        Page<Product> productPage = productRepository.findByProductSearchForm(pageable, productSearchForm);
        model.addAttribute("productPage", productPage);
        model.addAttribute("authenticated", account != null);
        return "product/product-list";
    }

    @GetMapping("/product/{id}")
    public String getProductDetails(@PathVariable Long id, @CurrentAccount Account account, Model model) {
        Product product = productService.getProduct(id);
        model.addAttribute("product", product);
        model.addAttribute("minQuantity", appProperties.getMinQuantity());
        model.addAttribute("maxQuantity", appProperties.getMaxQuantity());
        model.addAttribute("authenticated", account != null);
        return "product/product-details";
    }

}
