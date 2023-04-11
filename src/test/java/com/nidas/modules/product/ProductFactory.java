package com.nidas.modules.product;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Component
public class ProductFactory {

    @Autowired private ProductRepository productRepository;

    public Product createProduct() {
        List<ProductImage> productImages = createProductImages();
        List<ProductDetails> productDetails = createProductDetails();

        Product product = new Product();
        product.setMainCategory(MainCategory.MEN);
        product.setSubCategory(SubCategory.LIFESTYLE);
        product.setName("상품명");
        product.setMaterial("원료");
        product.setMadeIn("생산지");
        product.setWashing("세탁법");
        product.setPrice(50000);
        product.setDescription("상세내용");
        product.setThumbnail(productImages.get(0).getImage());
        product.setImages(productImages);
        product.setDetails(productDetails);
        return productRepository.save(product);
    }

    public List<ProductImage> createProductImages() {
        File [] files = new File("./src/test/resources/images").listFiles();
        List<ProductImage> productImages = new ArrayList<>();

        for (int i = 0; i < files.length; i++){
            Path path = files[i].toPath();
            if (Files.exists(path)) {
                ProductImage productImage = new ProductImage();
                try {
                    byte[] fileContent = Files.readAllBytes(path);
                    String image = new String(Base64.getEncoder().encode(fileContent));
                    productImage.setImage(image);
                } catch (IOException e) {
                    e.printStackTrace();
                }
                productImages.add(productImage);
            }
        }
        return productImages;
    }

    private List<ProductDetails> createProductDetails() {
        ProductDetails[] productDetails = new ProductDetails[6];
        for (int i = 0; i < productDetails.length; i++) {
             productDetails[i] = new ProductDetails();
        }

        productDetails[0].setColor(Color.BEIGE);
        productDetails[0].setSize(Size.TWO_HUNDRED_FIFTY);
        productDetails[0].setStock(100);

        productDetails[1].setColor(Color.BEIGE);
        productDetails[1].setSize(Size.TWO_HUNDRED_SIXTY);
        productDetails[1].setStock(100);

        productDetails[2].setColor(Color.BEIGE);
        productDetails[2].setSize(Size.TWO_HUNDRED_SEVENTY);
        productDetails[2].setStock(100);

        productDetails[3].setColor(Color.BLACK);
        productDetails[3].setSize(Size.TWO_HUNDRED_FIFTY);
        productDetails[3].setStock(100);

        productDetails[4].setColor(Color.BLACK);
        productDetails[4].setSize(Size.TWO_HUNDRED_SIXTY);
        productDetails[4].setStock(100);

        productDetails[5].setColor(Color.BLACK);
        productDetails[5].setSize(Size.TWO_HUNDRED_SEVENTY);
        productDetails[5].setStock(100);

        return List.of(productDetails);
    }

}
