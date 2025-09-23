package com.example.publickeyinfrastructure.mapper;

import com.example.publickeyinfrastructure.dto.SubjectDTO;
import com.example.publickeyinfrastructure.model.Subject;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

@Component
public class SubjectMapper {

    private final ModelMapper mapper;

    public SubjectMapper(ModelMapper mapper) {
        this.mapper = mapper;
    }

    public SubjectDTO toDto(Subject subject) {
        return mapper.map(subject, SubjectDTO.class);
    }

    public Subject toEntity(SubjectDTO dto) {
        return mapper.map(dto, Subject.class);
    }
}
