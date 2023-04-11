package com.nidas.infra.exception;

import lombok.Getter;

@Getter
public class InvalidParameterException extends RuntimeException {

    public InvalidParameterException(String message) {
        super(message);
    }

}
