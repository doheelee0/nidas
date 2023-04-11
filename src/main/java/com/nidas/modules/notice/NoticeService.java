package com.nidas.modules.notice;

import com.nidas.infra.exception.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@Transactional
@RequiredArgsConstructor
public class NoticeService {

    private final NoticeRepository noticeRepository;
    private final ModelMapper modelMapper;

    public void write(NoticeForm noticeForm) {
        Notice newNotice = modelMapper.map(noticeForm, Notice.class);
        newNotice.setCreatedDateTime(LocalDateTime.now());
        noticeRepository.save(newNotice);
    }

    public Notice getNotice(Long id) {
        Notice notice = noticeRepository.findById(id).orElseThrow(() -> {
            throw new ResourceNotFoundException("존재하지 않는 공지사항입니다.");
        });
        return notice;
    }

    public void update(Notice notice, NoticeForm noticeForm) {
        modelMapper.map(noticeForm, notice);
    }

    public void delete(Notice notice) {
        noticeRepository.delete(notice);
    }

}
