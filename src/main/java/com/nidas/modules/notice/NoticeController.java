package com.nidas.modules.notice;

import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
public class NoticeController {

    private final NoticeService noticeService;
    private final NoticeRepository noticeRepository;
    private final ModelMapper modelMapper;

    @GetMapping("/notice-list")
    public String getNoticeList(@PageableDefault(size = 20, sort = "createdDateTime", direction = Sort.Direction.DESC) Pageable pageable,
                                @RequestParam(defaultValue = "") String keyword, Model model) {
        Page<Notice> noticePage = noticeRepository.findByTitleContainingIgnoreCaseOrContentContainingIgnoreCase(keyword, keyword, pageable);
        model.addAttribute("noticePage", noticePage);
        model.addAttribute("keyword", keyword);
        return "notice/notice-list";
    }

    @GetMapping("/admin/management/notice")
    public String getAdminNoticeList(@PageableDefault(size = 20, sort = "createdDateTime", direction = Sort.Direction.DESC) Pageable pageable,
                                     @RequestParam(defaultValue = "") String keyword, Model model) {
        Page<Notice> noticePage = noticeRepository.findByTitleContainingIgnoreCaseOrContentContainingIgnoreCase(keyword, keyword, pageable);
        model.addAttribute("noticePage", noticePage);
        model.addAttribute("keyword", keyword);
        return "notice/admin/notice-management";
    }

    @GetMapping("/admin/notice/write")
    public String writeNoticeForm(Model model) {
        model.addAttribute(new NoticeForm());
        return "notice/admin/write-notice";
    }

    @GetMapping("/admin/notice/{id}/update")
    public String updateNoticeForm(@PathVariable Long id, Model model) {
        Notice notice = noticeService.getNotice(id);
        model.addAttribute("id", id);
        model.addAttribute(modelMapper.map(notice, NoticeForm.class));
        return "notice/admin/update-notice";
    }

}