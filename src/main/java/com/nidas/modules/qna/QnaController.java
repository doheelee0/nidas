package com.nidas.modules.qna;

import com.nidas.modules.account.Account;
import com.nidas.modules.account.CurrentAccount;
import com.nidas.modules.qna.form.AdminQnaSearchForm;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;

@Controller
@RequiredArgsConstructor
public class QnaController {

    private final QnaRepository qnaRepository;

    @GetMapping("/mypage/qna-list")
    public String getQnaList(@CurrentAccount Account account, Model model) {
        List<Qna> qnaList = qnaRepository.findByAccount(account);
        model.addAttribute("qnaList", qnaList);
        model.addAttribute(account);
        return "qna/qna-list";
    }

    @GetMapping("/admin/management/qna")
    public String getAdminQnaList(@PageableDefault(size = 20) Pageable pageable,
                                  AdminQnaSearchForm adminQnaSearchForm, Model model) {
        Page<Qna> qnaPage = qnaRepository.findByAdminQnaSearchForm(adminQnaSearchForm, pageable);
        model.addAttribute("qnaPage", qnaPage);
        return "qna/admin/qna-management";
    }

}
