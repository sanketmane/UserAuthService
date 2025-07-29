package com.example.userauthservice.models;

import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@MappedSuperclass
public abstract class BaseModel {
    @Id
    // @GeneratedValue(strategy = GenerationType.IDENTITY)
    // this annotation is used to auto-generate primary key value
    // based on db's auto-increment feature.
    // For this case, id would be auto-incremented.
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Date createdAt;

    private Date lastUpdatedAt;

    private Status status;
}
