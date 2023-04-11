package com.nidas.modules.notice;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequiredArgsConstructor
public class NoticeRestController {

    private final NoticeService noticeService;

    @PostMapping("/admin/notice/write")
    public ResponseEntity writeNotice(@RequestBody @Valid NoticeForm noticeForm) {
        noticeService.write(noticeForm);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/admin/notice/{id}/update")
    public ResponseEntity updateNotice(@PathVariable Long id, @RequestBody @Valid NoticeForm noticeForm) {
        Notice notice = noticeService.getNotice(id);
        noticeService.update(notice, noticeForm);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/admin/notice/{id}/delete")
    public ResponseEntity deleteNotice(@PathVariable Long id) {
        Notice notice = noticeService.getNotice(id);
        noticeService.delete(notice);
        return ResponseEntity.ok().build();
    }

}
