package com.nidas.modules.qna;

import com.nidas.infra.exception.InvalidParameterException;
import com.nidas.modules.account.Account;
import com.nidas.modules.account.AccountService;
import com.nidas.modules.account.CurrentAccount;
import com.nidas.modules.product.Product;
import com.nidas.modules.product.ProductService;
import com.nidas.modules.qna.form.*;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class QnaRestController {

    private final AccountService accountService;
    private final ProductService productService;
    private final QnaService qnaService;
    private final QnaRepository qnaRepository;

    @PostMapping("/product/{productId}/write/qna")
    public ResponseEntity writeQna(@PathVariable("productId") Long productId, @CurrentAccount Account account,
                                   @RequestBody @Valid QnaWriteForm qnaWriteForm, Errors errors) {
        if (errors.hasErrors()) {
            throw new InvalidParameterException(errors.getAllErrors().get(0).getDefaultMessage());
        }
        Product product = productService.getProduct(productId);
        qnaService.writeQna(product, account, qnaWriteForm);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/product/{productId}/qna")
    public ResponseEntity getQna(@PathVariable("productId") Long productId, @CurrentAccount Account account,
                                 @PageableDefault(size = 20, sort = "createdDateTime", direction = Sort.Direction.DESC) Pageable pageable) {
        Product product = productService.getProduct(productId);
        Page<Qna> qnaPage = qnaRepository.findByProduct(product, pageable);
        return ResponseEntity.ok().body(putQnaPageInfoToMap(account, qnaPage));
    }

    private Map<String, Object> putQnaPageInfoToMap(Account account, Page<Qna> qnaPage) {
        List<QnaForm> qnaList = qnaPage.getContent().stream().map(qna -> {
            QnaForm qnaForm = new QnaForm();
            qnaForm.setQna(qna, account);
            return qnaForm;
        }).collect(Collectors.toList());
        int startPage = qnaPage.getNumber() / 10 * 10;
        int endPage = Math.min(startPage + 9, qnaPage.getTotalPages() - 1);

        Map<String, Object> map = new HashMap<>();
        map.put("qnaList", qnaList);
        map.put("startPage", startPage);
        map.put("endPage", endPage);
        map.put("totalCount", qnaPage.getTotalElements());
        map.put("currentPage", qnaPage.getNumber());
        map.put("hasPrevious", qnaPage.hasPrevious());
        map.put("hasNext", qnaPage.hasNext());
        return map;
    }

    @PostMapping("/qna/{id}/delete")
    public ResponseEntity deleteQna(@PathVariable Long id, @CurrentAccount Account account) {
        Qna qna = qnaService.getQna(id, account);
        qnaService.delete(qna);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/admin/management/account/{id}/qna")
    public ResponseEntity getAccountQnaList(@PathVariable("id") Account account) {
        List<AdminQnaInfo> qnaList = qnaRepository.findByAccount(account).stream().map(qna -> {
            AdminQnaInfo adminQnaInfo = new AdminQnaInfo();
            adminQnaInfo.setQnaInfo(qna);
            return adminQnaInfo;
        }).collect(Collectors.toList());
        return ResponseEntity.ok().body(qnaList);
    }

    @PostMapping("/admin/qna/reply")
    public ResponseEntity replyQna(@Valid @RequestBody QnaReplyForm qnaReplyForm, Errors errors) {
        if (errors.hasErrors()) {
            throw new InvalidParameterException(errors.getAllErrors().get(0).getDefaultMessage());
        }
        Account account = accountService.getAccount(qnaReplyForm.getAccountId());
        Qna qna = qnaService.getQna(qnaReplyForm.getQnaId(), account);
        qnaService.replyQna(qna, qnaReplyForm.getContent());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/admin/qna/reply/update")
    public ResponseEntity updateReply(@Valid @RequestBody QnaReplyForm qnaReplyForm, Errors errors) {
        if (errors.hasErrors()) {
            throw new InvalidParameterException(errors.getAllErrors().get(0).getDefaultMessage());
        }
        Account account = accountService.getAccount(qnaReplyForm.getAccountId());
        Qna qna = qnaService.getQna(qnaReplyForm.getQnaId(), account);
        qnaService.updateReply(qna, qnaReplyForm.getContent());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/admin/qna/reply/delete")
    public ResponseEntity deleteReply(@Valid @RequestBody QnaIdForm qnaIdForm, Errors errors) {
        if (errors.hasErrors()) {
            throw new InvalidParameterException(errors.getAllErrors().get(0).getDefaultMessage());
        }
        Account account = accountService.getAccount(qnaIdForm.getAccountId());
        Qna qna = qnaService.getQna(qnaIdForm.getQnaId(), account);
        qnaService.deleteReply(qna);
        return ResponseEntity.ok().build();
    }

}
